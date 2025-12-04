use std::{collections::BTreeMap, marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use miette::miette;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;
use tokio::sync::Mutex;
use wasmtime::{Engine, Store, component::{Linker, ResourceAny}};
use wasmtime_wasi::WasiView;
use wasmtime_wasi_io::IoView;
use crate::proxy::{RiverContext, filters::types::{RequestFilterMod, RequestModifyMod, ResponseModifyMod}, plugins::{g::{self, App, exports::river::proxy::filter_factory::{Config, FilterInstance, GuestFilterInstance}}, host::HostFunctions, store::{ModuleState, SessionCtx, WasmArtifact}}};


pub trait TraitModuleState: WasiView + IoView + HostFunctions + Default + 'static { }

impl<T> TraitModuleState for T 
where 
    T: WasiView + IoView + HostFunctions + Default + 'static
{}

pub struct WasmModule<T: 'static = ModuleState> {
    artifact: WasmArtifact,
    linker: Linker<T> 
}

impl<T> Clone for WasmModule<T> {
    fn clone(&self) -> Self {
        Self {
            artifact: self.artifact.clone(),
            linker: self.linker.clone(),
        }
    }
}

impl<T: TraitModuleState> WasmModule<T> {

    pub fn new(artifact: WasmArtifact, linker: Linker<T>) -> Self {
        Self { artifact, linker }
    }

    pub fn pick(&self, name: &str, cfg: &BTreeMap<String, String>, state: T) -> miette::Result<Option<WasmFilterState<T>>> {
        
        let mut store = Store::new(&self.artifact.engine, state);

        let instance = g::App::instantiate(&mut store, &self.artifact.component, &self.linker)
            .map_err(|err| miette!("{err}"))?;
        
        if let Some((resource, self_type)) = instance
            .river_proxy_filter_factory()
            .call_create(&mut store, name, &cfg.clone().into_iter().collect::<Vec<_>>())
            .map_err(|err| miette!("{err}"))?
            .map_err(|err| miette!("module('{name}') return error on create filter: {err}"))?
        {
            Ok(Some(WasmFilterState {
                instance,
                resource,
                self_type: self_type.into(),
                store
            }))
        }
        else {
            Ok(None)
        }
    }

}

#[derive(Clone, Copy, PartialEq)]
pub enum FilterType {
    Filter,
    OnRequest,
    OnResponse
}

pub struct WasmFilterState<T: 'static> {
    pub store: Store<T>,
    pub instance: g::App,
    pub resource: ResourceAny,
    pub self_type: FilterType
}

pub struct WasmInvoker<T: 'static = ModuleState> {
    pub module: WasmModule<T>, 
    pub filter_name: String,
    pub config: BTreeMap<String, String>,
}

impl<T> Clone for WasmInvoker<T> {
    fn clone(&self) -> Self {
        Self {
            module: self.module.clone(),
            filter_name: self.filter_name.clone(),
            config: self.config.clone()
        }
    }
}


impl<T: TraitModuleState> WasmInvoker<T> {

    pub fn new(module: WasmModule<T>, filter_name: String, config: BTreeMap<String, String>) -> Self {
        Self { config, filter_name, module }
    }

    pub fn get_filter_type(&self) -> miette::Result<FilterType> {
        
        let state = T::default();

        let filter_state = self.module.pick(&self.filter_name, &self.config, state)?
            .ok_or_else(|| miette!("Invariant violated: filter instance not found"))?;

        Ok(filter_state.self_type)
    }

    fn execute<F, R>(&self, state: T, func: F) -> pingora::Result<R>
    where
        F: FnOnce(
            &GuestFilterInstance, 
            &mut Store<T>, 
            ResourceAny
        ) -> wasmtime::Result<std::result::Result<R, String>>,
    {
        
        let mut filter_state = self.module.pick(&self.filter_name, &self.config, state)
            .map_err(|e| Self::make_err("Failed to instantiate module", e))?
            .ok_or_else(|| Self::make_err("Invariant violated: filter instance not found", ""))?;

            
        let factory = filter_state.instance.river_proxy_filter_factory();
        let filter = factory.filter_instance();

        
        let wasm_result = func(&filter, &mut filter_state.store, filter_state.resource)
            .map_err(|e| Self::make_err("Wasm runtime trap/error", e))?;

            
        wasm_result.map_err(|e| Self::make_err("Filter execution error", e))
    }
    

    fn on_request(&self, state: T) -> pingora::Result<()> {
        self.execute(state, |f, s, r| f.call_on_request(s, r))
    }
    
    fn filter(&self, state: T) -> pingora::Result<bool> {
        self.execute(state, |f, s, r| f.call_filter(s, r))
    }
    
    fn on_response(&self, state: T) -> pingora::Result<()> {
        self.execute(state, |f, s, r| f.call_on_response(s, r))
    }

    fn make_err(msg: &'static str, context: impl std::fmt::Display) -> pingora::BError {
        pingora::Error::new(pingora::ErrorType::Custom(msg)) 
            .more_context(context.to_string())
    }
}


#[async_trait]
impl RequestFilterMod for WasmInvoker {
    async fn request_filter(&self, session: &mut Session, ctx: &mut RiverContext) -> pingora::Result<bool> {

        let session_state = SessionCtx {
            req_header: None,
            res_headers: None,
            session: session.into()
        };
        
        let state = ModuleState {
            session: Some(session_state),
            ..Default::default()
        };

        Ok(false)
    }
}

#[async_trait]
impl ResponseModifyMod for WasmInvoker {
    fn upstream_response_filter(
        &self,
        session: &mut Session,
        header: &mut ResponseHeader,
        ctx: &mut RiverContext,
    ) {
        let session_state = SessionCtx {
            req_header: None,
            res_headers: Some(header.into()),
            session: session.into()
        };
        
        let state = ModuleState {
            session: Some(session_state),
            ..Default::default()
        };

        
    }   
}


#[async_trait]
impl RequestModifyMod for WasmInvoker {
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        header: &mut RequestHeader,
        ctx: &mut RiverContext,
    ) -> pingora::Result<()> {
        
        let session_state = SessionCtx {
            req_header: Some(header.into()),
            res_headers: None,
            session: session.into()
        };
        
        let state = ModuleState {
            session: Some(session_state),
            ..Default::default()
        };

        self.on_request(state)
    }
}




impl From<g::exports::river::proxy::filter_factory::FilterType> for FilterType {
    fn from(value: g::exports::river::proxy::filter_factory::FilterType) -> Self {
        match value {
            g::exports::river::proxy::filter_factory::FilterType::Filter => Self::Filter,
            g::exports::river::proxy::filter_factory::FilterType::Request => Self::OnRequest,
            g::exports::river::proxy::filter_factory::FilterType::Response => Self::OnResponse
        }
    }
}



#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use fqdn::FQDN;
    use wasmtime::Engine;
    use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxView};

    use crate::{config::common_types::definitions::PluginSource, proxy::plugins::store::WasmPluginStore};

    #[derive(Default)]
    pub struct MockState {
        pub ctx: WasiCtx,
        pub table: ResourceTable,
    }

    impl WasiView for MockState {
        fn ctx(&mut self) -> WasiCtxView<'_> {
            WasiCtxView { ctx: &mut self.ctx, table: &mut self.table }
        }
    }

    impl IoView for MockState {
        fn table(&mut self) -> &mut ResourceTable { &mut self.table }
    }

    impl HostFunctions for MockState {
        fn get_path(&self) -> String {
            "/hubabuba".to_string()
        }
    }

    use super::*;
    #[tokio::test]
    async fn test_wasm() {
        
        let artifact = WasmPluginStore::create_artifact(
            FQDN::from_str("example").unwrap(), 
            //request_filter.wasm from examples/wasm-module
            &PluginSource::File("./assets/request_filter.wasm".into()), 
            &Engine::default()
        ).await.unwrap();

        let filter_name = "my_filter".to_string();

        {
            let module = WasmPluginStore::create_module(&artifact).unwrap();
            
            let config = BTreeMap::from([("forbidden".to_string(), "hubabuba".to_string())]);
            
            let state = MockState::default();

            let invoker = WasmInvoker::new(module, filter_name.clone(), config);

            assert!(invoker.filter(state).unwrap());
        }


        {
            let module = WasmPluginStore::create_module(&artifact).unwrap();

            let config = BTreeMap::from([("forbidden".to_string(), "not hubabuba".to_string())]);
            
            let state = MockState::default();

            let invoker = WasmInvoker::new(module, filter_name.clone(), config);

            assert!(!invoker.filter(state).unwrap());
        }

        let filter_name = "response_logger".to_string();

        {
            let module = WasmPluginStore::create_module(&artifact).unwrap();

            let config = BTreeMap::from([("forbidden".to_string(), "not hubabuba".to_string())]);
            
            let state = MockState::default();

            let invoker = WasmInvoker::new(module, filter_name.clone(), config);

            invoker.on_response(state).unwrap();
        }
    }
}
