use wasmtime::{StoreContextMut, component::{Linker, LinkerInstance}};
use wasmtime_wasi::WasiView;
use wasmtime_wasi_io::IoView;

use crate::proxy::plugins::{module::TraitModuleState, store::ModuleState};

pub trait HostFunctions {
    fn get_path(&self) -> String;
}

pub struct PluginHost;

impl PluginHost {

    pub fn register_enviroment<T: TraitModuleState>(linker: &mut Linker<T>) -> wasmtime::Result<()> {
        
        wasmtime_wasi::p2::add_to_linker_sync(linker)?;
        
        Self::register_logger(linker.root().instance("river:proxy/logger")?)?;
        Self::register_context(linker.root().instance("river:proxy/context")?)?;

        Ok(())
    }

    fn register_context<T: TraitModuleState>(mut logger: LinkerInstance<'_, T> ) -> wasmtime::Result<()> { 
        
        logger.func_wrap("get-path", |ctx, (): ()| -> wasmtime::Result<(String,)> {
            Ok((ctx.data().get_path(),))
        })?;
        
        Ok(())
    }

    fn register_logger<T: WasiView + IoView>(mut logger: LinkerInstance<'_, T> ) -> wasmtime::Result<()> {

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

impl HostFunctions for ModuleState {
    fn get_path(&self) -> String {
        if let Some(req) = self.session.as_ref().and_then(|s| s.req_header) {
            let path = unsafe { req.as_ref() }.uri.path();
            path.to_string()
        }
        else {
            panic!("invariant violated: session was null on filter phase");
        }
    }
}