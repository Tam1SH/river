use std::collections::BTreeMap;

use async_trait::async_trait;
use tokio::sync::Mutex;
use wasmtime::{Engine, Store, component::{Component, Linker, bindgen}};
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxView, WasiView};
use wasmtime_wasi_io::IoView;

use crate::proxy::extract_val;

mod generated {
    use super::*;
    bindgen!({
        world: "filter-world",
        path: "./wit/request.wit",
    });
}

pub struct Request {
    pub path: String,
    pub method: String,
    pub headers: BTreeMap<String, String>,
}

struct ModuleState {
    ctx: WasiCtx,
    table: ResourceTable,
}

impl WasiView for ModuleState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView { ctx: &mut self.ctx, table: &mut self.table }
    }
}


impl IoView for ModuleState {
    fn table(&mut self) -> &mut ResourceTable { &mut self.table }
}

#[async_trait]
pub trait WasmModuleFilterTrait: Send + Sync {
    async fn call_filter(&self, req: Request) -> wasmtime::Result<bool>;
}

pub struct WasmModuleFilter {
    store: Mutex<Store<ModuleState>>,
    instance: generated::FilterWorld
}

#[async_trait]
impl WasmModuleFilterTrait for WasmModuleFilter {
    async fn call_filter(&self, req: Request) -> wasmtime::Result<bool> {
        let mut store = self.store.lock().await;
        let store = &mut *store;
        self.instance.call_filter(store, &req.into())
    }
}

impl WasmModuleFilter {
    pub fn new(engine: &Engine, path: &str) -> wasmtime::Result<Self> {
        let component =  Component::from_file(engine, path)?;
        
        let mut builder = WasiCtx::builder();
        
        let mut store: Store<ModuleState> = Store::new(engine, 
            ModuleState {
                ctx: builder.build(),
                table: ResourceTable::new(),
            }
        );

        let mut linker: Linker<ModuleState> = Linker::new(engine);

        wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;
        WasmModuleFilter::register_logger(linker.root().instance("river:request/logger")?)?;

        let instance = generated::FilterWorld::instantiate(&mut store, &component, &linker)?;

        Ok(Self {
            store: store.into(),
            instance,
        })
    }

    pub fn from_settings(mut settings: BTreeMap<String, String>) -> pingora::Result<Self> {
        let path = extract_val("path", &mut settings)?;
        
        let engine = Engine::default();
        let this = Self::new(
                &engine,
                &path
            ).map_err(|e| {
                tracing::error!("Error loading wasm module from '{path}': {e:?}");
                pingora::Error::new_str("Error loading wasm module")
            })?;

        tracing::info!("Loaded wasm module from path: '{path}'");

        Ok(this)
    }


    fn register_logger(mut logger: wasmtime::component::LinkerInstance<'_, ModuleState> ) -> wasmtime::Result<()> {

        logger.func_wrap("info", |_, (message, ): (String, )| {
            tracing::info!("WASM LOG: {}", message);
            Ok(())
        })?;

        logger.func_wrap("error", |_, (message, ): (String, )| {
            tracing::error!("WASM LOG: {}", message);
            Ok(())
        })?;

        logger.func_wrap("debug", |_, (message, ): (String, )| {
            tracing::debug!("WASM LOG: {}", message);
            Ok(())
        })?;

        Ok(())
    }
}

impl From<Request> for generated::Request {
    fn from(req: Request) -> Self {
        Self {
            path: req.path,
            method: req.method,
            headers: req.headers.into_iter().map(|(k, v)| {
                generated::river::request::r::Pair {
                    name: k,
                    value: v,
                }
            }).collect(),
        }
    }
}

#[cfg(test)]
mod tests {


    use super::*;
    #[tokio::test]
    async fn test_wasm() {
        
        let engine = Engine::default();
        //request_filter.wasm from examples/wasm-module
        let component = WasmModuleFilter::new(
            &engine,
            "./assets/request_filter.wasm"
        ).unwrap();
        
        let ping = component
            .call_filter(
                Request { 
                    path: "/something".to_string(),
                    headers: BTreeMap::new(),
                    method: "GET".to_string(),
                }
            ).await.unwrap();

        assert!(!ping);

        let ping = component
            .call_filter(
                Request { 
                    path: "/hubabuba".to_string(),
                    headers: BTreeMap::new(),
                    method: "GET".to_string(),
                }
            ).await.unwrap();

        assert!(ping);
    }
}
