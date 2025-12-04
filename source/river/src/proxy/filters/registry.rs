use std::collections::{BTreeMap, HashMap};
use fqdn::FQDN;
use pingora_core::{Error, ErrorType, Result};

use crate::proxy::{
    RequestFilterMod, RequestModifyMod, ResponseModifyMod, plugins::module::WasmModule,
};

pub enum FilterInstance {
    Action(Box<dyn RequestFilterMod>),
    Request(Box<dyn RequestModifyMod>),
    Response(Box<dyn ResponseModifyMod>),
}

#[allow(clippy::large_enum_variant)]
pub enum RegistryFilterContainer {
    Builtin(FilterInstance),
    Plugin(WasmModule)
}

type FiltersContainerFactoryFn = Box<dyn Fn(BTreeMap<String, String>) -> Result<RegistryFilterContainer> + Send + Sync>;

/// The central repository for all available filter blueprints (factories).
///
/// This registry maps unique string identifiers (e.g., `"river.filters.rate-limit"`)
/// to constructor functions (factories). It is used during the configuration build phase
/// to instantiate concrete filter objects for specific processing chains.
///
/// # key characteristics:
/// - **Storage**: Holds factories, not active filter instances.
/// - **Scope**: Contains both built-in native filters and dynamically loaded WASM plugins.
/// - **Usage**: Consulted when `compile_rules` encounters a `filter name="..."` directive.
#[derive(Default)]
pub struct FilterRegistry {
    factories: HashMap<FQDN, FiltersContainerFactoryFn>,
}

impl FilterRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_factory(&mut self, name: FQDN, factory: FiltersContainerFactoryFn) {
        if self.factories.insert(name.clone(), factory).is_some() {
            tracing::warn!("Filter factory '{}' was overwritten", name);
        }
    }

    pub fn build(&self, name: &FQDN, settings: BTreeMap<String, String>) -> Result<RegistryFilterContainer> {
        let factory = self.factories.get(name).ok_or_else(|| {
            Error::new(ErrorType::Custom("Filter is not registered in the binary")).more_context(format!("filter name: '{name}'"))
        })?;

        factory(settings)
    }

    pub fn contains(&self, name: &FQDN) -> bool {
        self.factories.contains_key(name)
    }
}



#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::str::FromStr;

    use async_trait::async_trait;

    use fqdn::FQDN;
    use pingora_core::Result;
    use pingora_proxy::Session;
    use crate::config::common_types::definitions::{ConfiguredFilter, DefinitionsTable, FilterChain};
    use crate::proxy::RiverContext;
    use crate::proxy::filters::chain_resolver::ChainResolver;
    use crate::proxy::filters::generate_registry::load_registry;
    use crate::proxy::filters::registry::{FilterInstance, FilterRegistry, RegistryFilterContainer};
    use crate::proxy::{RequestModifyMod, RequestFilterMod};
    
    struct MockHeaderFilter;

    impl MockHeaderFilter {
        fn from_settings(mut s: BTreeMap<String, String>) -> Result<Self> {
            s.remove("key").unwrap();
            s.remove("value").unwrap();
            Ok(Self)
        }
    }

    #[async_trait]
    impl RequestModifyMod for MockHeaderFilter {
        async fn upstream_request_filter(&self, _s: &mut Session, _h: &mut pingora_http::RequestHeader, _ctx: &mut RiverContext) -> Result<()> { Ok(()) }
    }

    struct MockBlockFilter;

    impl MockBlockFilter {
        fn from_settings(_: BTreeMap<String, String>) -> Result<Self> { Ok(Self) }
    }

    #[async_trait]
    impl RequestFilterMod for MockBlockFilter {
        async fn request_filter(&self, _s: &mut Session, _ctx: &mut RiverContext) -> Result<bool> { Ok(false) }
    }

    fn setup_registry() -> FilterRegistry {
        let mut reg = FilterRegistry::new();
        
        reg.register_factory(FQDN::from_str("river.req.add_header").unwrap(), Box::new(|s| {
            let f = MockHeaderFilter::from_settings(s)?;
            Ok(RegistryFilterContainer::Builtin(FilterInstance::Request(Box::new(f))))
        }));
        
        reg.register_factory(FQDN::from_str("river.sec.block").unwrap(), Box::new(|s| {
            let f = MockBlockFilter::from_settings(s)?;
            Ok(RegistryFilterContainer::Builtin(FilterInstance::Action(Box::new(f))))
        }));
        
        reg
    }

     #[test]
    fn test_builtin_filters_population() {
        
        let mut definitions = DefinitionsTable::default();
        
        
        assert!(definitions.available_filters.is_empty());

        
        let _registry = load_registry(&mut definitions);
        
        assert!(definitions.available_filters.contains(&FQDN::from_str("river.filters.block-cidr-range").unwrap()));
        assert!(definitions.available_filters.contains(&FQDN::from_str("river.response.upsert-header").unwrap()));
        assert!(definitions.available_filters.contains(&FQDN::from_str("river.response.remove-header").unwrap()));
        assert!(definitions.available_filters.contains(&FQDN::from_str("river.request.upsert-header").unwrap()));
        assert!(definitions.available_filters.contains(&FQDN::from_str("river.request.remove-header").unwrap()));

        assert_eq!(definitions.available_filters.len(), 5);
    }


    #[tokio::test]
    async fn test_compile_success() {
        
        let mut definitions_table = DefinitionsTable::default();

        // Register available definitions (emulating `def name="..."`)
        definitions_table.available_filters.insert(FQDN::from_str("river.req.add_header").unwrap());
        definitions_table.available_filters.insert(FQDN::from_str("river.sec.block").unwrap());

        // Construct the chain
        let mut header_args = HashMap::new();
        header_args.insert("key".to_string(), "X-Foo".to_string());
        header_args.insert("value".to_string(), "Bar".to_string());

        let filters = vec![
            ConfiguredFilter {
                name: FQDN::from_str("river.sec.block").unwrap(),
                args: HashMap::new(),
            },
            ConfiguredFilter {
                name: FQDN::from_str("river.req.add_header").unwrap(),
                args: header_args,
            },
        ];

        definitions_table.insert_chain(
            "main_pipeline".to_string(),
            FilterChain { filters }
        );

        let registry = setup_registry();

        let resolver = ChainResolver::new(definitions_table, registry).unwrap();
        
        let chain = resolver.resolve("main_pipeline").expect("Chain not found");
        
        assert_eq!(chain.actions.len(), 1, "Should have 1 action filter (block)");
        assert_eq!(chain.req_mods.len(), 1, "Should have 1 request modifier (add_header)");
        assert_eq!(chain.res_mods.len(), 0, "Should have 0 response modifiers");
    }

    #[tokio::test]
    async fn test_compile_fail_unknown_definition() {
        
        let mut definitions_table = DefinitionsTable::default();

        definitions_table.available_filters.insert(FQDN::from_str("river.unknown_thing").unwrap());

        
        let registry = setup_registry();

        let res = ChainResolver::new(definitions_table, registry);
        
        assert!(res.is_err());
        let err_msg = res.err().unwrap().to_string();
        
        assert!(
            err_msg.contains("Filter 'river.unknown_thing' is defined but not registered"),
            "Unexpected error message: {}", err_msg
        );
    }

    #[tokio::test]
    async fn test_instantiation_failure() {
        let mut reg = FilterRegistry::new();
        reg.register_factory(FQDN::from_str("river.always_fail").unwrap(), Box::new(|_| {
            Err(pingora_core::Error::new(pingora_core::ErrorType::Custom("Init failed")))
        }));
        
        let mut table = DefinitionsTable::default();
        table.available_filters.insert(FQDN::from_str("river.always_fail").unwrap());
        table.insert_chain("test", FilterChain {
            filters: vec![ConfiguredFilter {
                name: FQDN::from_str("river.always_fail").unwrap(),
                args: HashMap::new()
            }]
        });

        let resolver = ChainResolver::new(table, reg).unwrap();
        let err = resolver.resolve("test").err().unwrap();

        assert!(err.to_string().contains("Failed to build filter 'river.always_fail' in chain 'test'"));
    }
}
