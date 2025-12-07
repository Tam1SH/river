use crate::proxy::{
    filters::{
        registry::{FilterInstance, FilterRegistry, RegistryFilterContainer},
        types::{RequestFilterMod, RequestModifyMod, ResponseModifyMod},
    },
    plugins::module::{FilterType, WasmInvoker},
};
use miette::{miette, Context, IntoDiagnostic, Result};
use motya_config::common_types::{definitions::FilterChain, definitions_table::DefinitionsTable};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::Mutex;


#[derive(Default)]
pub struct RuntimeChain {
    pub actions: Vec<Box<dyn RequestFilterMod>>,
    pub req_mods: Vec<Box<dyn RequestModifyMod>>,
    pub res_mods: Vec<Box<dyn ResponseModifyMod>>,
}

#[derive(Clone, Default)]
pub struct ChainResolver {
    table: DefinitionsTable,
    registry: Arc<Mutex<FilterRegistry>>,
}

impl ChainResolver {
    pub async fn new(
        table: DefinitionsTable,
        registry: Arc<Mutex<FilterRegistry>>,
    ) -> Result<Self> {
        let registry_ = registry.lock().await;

        for (chain_name, chain) in table.get_chains() {
            for filter in &chain.filters {
                if !registry_.contains(&filter.name) {
                    return Err(miette!(
                        "Chain '{}' references unknown filter '{}'. Did you forget to load a plugin?",
                        chain_name,
                        filter.name
                    ));
                }
            }
        }

        for filter_name in table.get_available_filters() {
            if !registry_.contains(filter_name) {
                return Err(miette!(
                    "Filter '{}' is defined but not registered.",
                    filter_name
                ));
            }
        }

        drop(registry_);

        Ok(Self { table, registry })
    }

    pub async fn resolve(&self, chain_name: &str) -> Result<RuntimeChain> {
        let chain_cfg = self
            .table
            .get_chains()
            .get(chain_name)
            .ok_or_else(|| miette!("Chain '{}' not found in definitions table", chain_name))?;

        self.build_chain(chain_cfg, chain_name).await
    }

    async fn build_chain(&self, chain: &FilterChain, context_name: &str) -> Result<RuntimeChain> {
        let mut runtime_chain = RuntimeChain::default();

        for filter_cfg in &chain.filters {
            let settings: BTreeMap<String, String> = filter_cfg
                .args
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();

            let registry = self.registry.lock().await;
            let container = registry
                .build(&filter_cfg.name, settings.clone())
                .into_diagnostic()
                .wrap_err_with(|| {
                    format!(
                        "Failed to build filter '{}' in chain '{}'",
                        filter_cfg.name, context_name
                    )
                })?;

            match container {
                RegistryFilterContainer::Builtin(builtin) => match builtin {
                    FilterInstance::Action(f) => runtime_chain.actions.push(f),
                    FilterInstance::Request(f) => runtime_chain.req_mods.push(f),
                    FilterInstance::Response(f) => runtime_chain.res_mods.push(f),
                },
                RegistryFilterContainer::Plugin(plugin) => {
                    let (_plugin_name, filter_name) = filter_cfg
                        .name
                        .as_c_str()
                        .to_str()
                        .expect("invariant violated: not a valid UTF-8")
                        .split_once('.')
                        .ok_or_else(|| {
                            miette!(
                                "Invalid filter format: '{}'. Expected 'plugin.filter'",
                                filter_cfg.name
                            )
                        })?;

                    let invoker = WasmInvoker::new(plugin, filter_name.to_string(), settings);

                    match invoker.get_filter_type()? {
                        FilterType::Filter => Box::new(invoker),
                        FilterType::OnRequest => Box::new(invoker),
                        FilterType::OnResponse => Box::new(invoker),
                    };
                }
            }
        }

        Ok(runtime_chain)
    }
}
