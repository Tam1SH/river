use fqdn::FQDN;
use futures_util::future::join_all;
use miette::{miette, Context, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;
use std::{collections::HashMap, ptr::NonNull, sync::Arc};
use wasmtime::{
    component::{Component, Linker},
    Engine,
};
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxView, WasiView};
use wasmtime_wasi_io::IoView;

use crate::proxy::{
    filters::registry::{FilterRegistry, RegistryFilterContainer},
    plugins::{host::PluginHost, module::{TraitModuleState, WasmModule}},
};
use motya_config::common_types::{definitions::PluginSource, definitions_table::DefinitionsTable};

use super::loader::PluginLoader;


#[derive(Clone)]
pub struct WasmArtifact {
    pub _name: FQDN,
    pub component: Component,
    pub engine: Engine,
}

pub struct WasmPluginStore {
    artifacts: HashMap<FQDN, Arc<WasmArtifact>>,
}

impl WasmPluginStore {
    /// Compiles the Wasm modules based on the provided definitions table.
    ///
    /// Note that this method only prepares the modules. The filter names defined
    /// in the configuration are registered later via [`WasmPluginStore::register_into`].
    pub async fn compile(table: &DefinitionsTable) -> Result<Self> {
        let engine = Engine::default();

        let futures = table.get_plugins().iter().map(|(name, def)| {
            let engine = engine.clone();
            let name = name.clone();
            let source = def.source.clone();

            async move {
                let artifact =
                    WasmPluginStore::create_artifact(name.clone(), &source, &engine).await?;
                Ok::<_, miette::Report>((name, Arc::new(artifact)))
            }
        });

        let results = join_all(futures).await;

        let mut artifacts = HashMap::new();
        for res in results {
            let (name, artifact) = res?;
            artifacts.insert(name, artifact);
        }

        tracing::info!(
            "WasmPluginFactory initialized with {} plugins",
            artifacts.len()
        );

        Ok(Self { artifacts })
    }

    /// Iterates over the definitions `table` to find filter definitions and
    /// registers them into the provided `registry`.
    pub fn register_into(&self, registry: &mut FilterRegistry) {
        for (name, artifact) in &self.artifacts {
            let artifact_ref = artifact.clone();

            let name = name.clone();
            registry.register_factory(
                name.clone(),
                Box::new(move |_| {
                    let module = Self::create_module(&artifact_ref).map_err(|e| {
                        pingora::Error::new(pingora::ErrorType::Custom("Can't create wasm module"))
                            .more_context(format!("artifact name: '{name}'. error: {e}"))
                    })?;

                    Ok(RegistryFilterContainer::Plugin(module))
                }),
            );
        }
    }

    pub async fn create_artifact(
        name: FQDN,
        source: &PluginSource,
        engine: &Engine,
    ) -> Result<WasmArtifact> {
        tracing::debug!("Preparing plugin '{}'...", name);

        PluginLoader::check_availability(source)
            .await
            .wrap_err_with(|| format!("Availability check failed for plugin '{}'", name))?;

        let bytes = PluginLoader::fetch_bytes(source)
            .await
            .wrap_err_with(|| format!("Download failed for plugin '{}'", name))?;

        tracing::debug!("Compiling plugin '{}' ({} bytes)...", name, bytes.len());

        let component = Component::from_binary(engine, &bytes).map_err(|err| miette!("{err}"))?;

        tracing::info!("Plugin '{}' loaded and compiled successfully", name);

        Ok(WasmArtifact {
            _name: name,
            component,
            engine: engine.clone(),
        })
    }

    pub fn create_module<T: TraitModuleState>(
        artifact: &WasmArtifact,
    ) -> wasmtime::Result<WasmModule<T>> {
        let mut linker: Linker<T> = Linker::new(&artifact.engine);

        PluginHost::register_enviroment(&mut linker)?;

        Ok(WasmModule::new(artifact.clone(), linker))
    }
}

#[derive(Default)]
pub struct ModuleState {
    pub ctx: WasiCtx,
    pub table: ResourceTable,
    pub session: Option<SessionCtx>,
}

unsafe impl Send for ModuleState {}
unsafe impl Sync for ModuleState {}

pub struct SessionCtx {
    pub _session: NonNull<Session>,
    pub req_header: Option<NonNull<RequestHeader>>,
    pub _res_headers: Option<NonNull<ResponseHeader>>,
}

impl WasiView for ModuleState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.ctx,
            table: &mut self.table,
        }
    }
}

impl IoView for ModuleState {
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }
}

#[cfg(test)]
mod tests {
    use motya_config::common_types::definitions::PluginDefinition;
    use motya_config::common_types::definitions_table::DefinitionsTable;

    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::str::FromStr;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const WASM_BYTES: &[u8] = include_bytes!("../../../assets/request_filter.wasm");

    fn create_rules_table(plugin_name: &str, source: PluginSource) -> DefinitionsTable {
        let mut plugins = HashMap::new();
        plugins.insert(
            FQDN::from_str(plugin_name).unwrap(),
            PluginDefinition {
                name: FQDN::from_str(plugin_name).unwrap(),
                source,
            },
        );

        DefinitionsTable::new(HashSet::new(), HashMap::new(), plugins, Default::default())
    }

    #[tokio::test]
    async fn test_factory_load_from_url_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .and(path("/filter.wasm"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/filter.wasm"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(WASM_BYTES))
            .mount(&mock_server)
            .await;

        let url = format!("{}/filter.wasm", mock_server.uri());
        let table = create_rules_table("test-plugin", PluginSource::Url(url));

        let factory = WasmPluginStore::compile(&table)
            .await
            .expect("Factory initialization failed");

        assert!(factory
            .artifacts
            .contains_key(&FQDN::from_str("test-plugin").unwrap()));

        let artifact = factory
            .artifacts
            .get(&FQDN::from_str("test-plugin").unwrap())
            .unwrap();
        assert_eq!(artifact._name, "test-plugin");
    }

    #[tokio::test]
    async fn test_factory_load_from_url_404() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let url = format!("{}/missing.wasm", mock_server.uri());
        let table = create_rules_table("missing-plugin", PluginSource::Url(url));

        let result = WasmPluginStore::compile(&table).await;

        assert!(result.is_err());
        let err = result.err().unwrap();

        assert!(err
            .to_string()
            .contains("Availability check failed for plugin 'missing-plugin'"));
    }

    #[tokio::test]
    async fn test_factory_compilation_error_invalid_bytes() {
        let mock_server = MockServer::start().await;

        let bad_bytes = b"this is not a wasm binary";

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bad_bytes.as_slice()))
            .mount(&mock_server)
            .await;

        let url = format!("{}/bad.wasm", mock_server.uri());
        let table = create_rules_table("bad-plugin", PluginSource::Url(url));

        let result = WasmPluginStore::compile(&table).await;

        assert!(result.is_err());
        let err = result.err().unwrap();

        assert!(err
            .to_string()
            .contains("failed to parse WebAssembly module"));
    }

    #[tokio::test]
    async fn test_factory_mixed_sources() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(WASM_BYTES))
            .mount(&mock_server)
            .await;

        let url = format!("{}/remote.wasm", mock_server.uri());

        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("local.wasm");
        tokio::fs::write(&file_path, WASM_BYTES).await.unwrap();

        let mut plugins = HashMap::new();

        plugins.insert(
            FQDN::from_str("remote").unwrap(),
            PluginDefinition {
                name: FQDN::from_str("remote").unwrap(),
                source: PluginSource::Url(url),
            },
        );

        plugins.insert(
            FQDN::from_str("local").unwrap(),
            PluginDefinition {
                name: FQDN::from_str("local").unwrap(),
                source: PluginSource::File(file_path),
            },
        );

        let table =
            DefinitionsTable::new(HashSet::new(), HashMap::new(), plugins, Default::default());

        let factory = WasmPluginStore::compile(&table)
            .await
            .expect("Should load mixed sources");

        assert!(factory
            .artifacts
            .contains_key(&FQDN::from_str("remote").unwrap()));
        assert!(factory
            .artifacts
            .contains_key(&FQDN::from_str("local").unwrap()));
    }
}
