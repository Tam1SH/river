use crate::proxy::filters::registry::{FilterInstance, FilterRegistry, RegistryFilterContainer};
use crate::proxy::filters::builtin::{
    cidr_range::CidrRangeFilter,
    request::{
        remove_headers::RemoveHeaderKeyRegex as RequestRemoveHeaderKeyRegex,
        rewrite_path::RewritePathRegex,
        strip_prefix::StripPrefix,
        upsert_headers::UpsertHeader as RequestUpsertHeader,
    },
    response::{
        remove_header::RemoveHeaderKeyRegex as ResponseRemoveHeaderKeyRegex,
        upsert_header::UpsertHeader as ResponseUpsertHeader,
    },
};
use motya_config::common_types::definitions_table::DefinitionsTable;
use motya_config::define_builtin_filters;


macro_rules! impl_registry_loader {
    (
        actions: { $($act_key:literal => $act_type:ty),* $(,)? }

        requests: { $($req_key:literal => $req_type:ty),* $(,)? }

        responses: { $($res_key:literal => $res_type:ty),* $(,)? }
    ) => {
        pub fn load_registry(definitions: &mut DefinitionsTable) -> FilterRegistry {
            let mut registry = FilterRegistry::new();

            $(
                let key = fqdn::fqdn!($act_key);
                definitions.insert_filter(key.clone());

                registry.register_factory(key, Box::new(|settings| {
                    let item = <$act_type>::from_settings(settings)?;
                    Ok(RegistryFilterContainer::Builtin(FilterInstance::Action(Box::new(item))))
                }));
            )*


            $(
                let key = fqdn::fqdn!($req_key);
                definitions.insert_filter(key.clone());

                registry.register_factory(key, Box::new(|settings| {
                    let item = <$req_type>::from_settings(settings)?;
                    Ok(RegistryFilterContainer::Builtin(FilterInstance::Request(Box::new(item))))
                }));
            )*

            $(
                let key = fqdn::fqdn!($res_key);
                definitions.insert_filter(key.clone());

                registry.register_factory(key, Box::new(|settings| {
                    let item = <$res_type>::from_settings(settings)?;
                    Ok(RegistryFilterContainer::Builtin(FilterInstance::Response(Box::new(item))))
                }));
            )*

            registry
        }
    };
}

define_builtin_filters!(impl_registry_loader);
