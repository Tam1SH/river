use crate::proxy::filters::builtin::{
    cidr_range::CidrRangeFilter, request::{
        remove_headers::RemoveHeaderKeyRegex as RequestRemoveHeaderKeyRegex, 
        upsert_headers::UpsertHeader as RequestUpsertHeader
    }, 
    response::{
        remove_header::RemoveHeaderKeyRegex as ResponseRemoveHeaderKeyRegex, 
        upsert_header::UpsertHeader as ResponseUpsertHeader
    }
};


macro_rules! generate_registry {
    (
        fn $fn_name:ident;

        $(
            actions: {
                $($action_key:literal => $action_type:ty),* $(,)?
            }
        )?

        $(
            requests: {
                $($req_key:literal => $req_type:ty),* $(,)?
            }
        )?

        $(
            responses: {
                $($res_key:literal => $res_type:ty),* $(,)?
            }
        )?
    ) => {
        /// Registers all built-in (native) filters into the registry.
        ///
        /// These filters are compiled directly into the binary. For implementation details
        /// and the list of available filters, refer to the [`proxy::filters::builtin`] module
        pub fn $fn_name(
            definitions: &mut $crate::config::common_types::definitions::DefinitionsTable
        ) -> $crate::proxy::filters::registry::FilterRegistry {
            let mut registry = $crate::proxy::filters::registry::FilterRegistry::new();
            use std::str::FromStr;
            use $crate::proxy::filters::registry::{RegistryFilterContainer, FilterInstance};
            $($(
                let action_key = fqdn::FQDN::from_str($action_key).expect("not valid FQDN");
                definitions.available_filters.insert(action_key.clone());

                registry.register_factory(action_key, Box::new(|settings| {
                    let item = <$action_type>::from_settings(settings)?;
                    Ok(RegistryFilterContainer::Builtin(FilterInstance::Action(Box::new(item))))
                }));
            )*)?

            $($(
                let req_key = fqdn::FQDN::from_str($req_key).expect("not valid FQDN");
                definitions.available_filters.insert(req_key.clone());
                registry.register_factory(req_key, Box::new(|settings| {
                    let item = <$req_type>::from_settings(settings)?;
                    Ok(RegistryFilterContainer::Builtin(FilterInstance::Request(Box::new(item))))
                }));
            )*)?

            $($(
                let res_key = fqdn::FQDN::from_str($res_key).expect("not valid FQDN");
                definitions.available_filters.insert(res_key.clone());
                registry.register_factory(res_key, Box::new(|settings| {
                    let item = <$res_type>::from_settings(settings)?;
                    Ok(RegistryFilterContainer::Builtin(FilterInstance::Response(Box::new(item))))
                }));
            )*)?

            registry
        }
    };
}


generate_registry! {
    fn load_registry;

    actions: {
        "river.filters.block-cidr-range" => CidrRangeFilter,
    }

    requests: {
        "river.request.upsert-header" => RequestUpsertHeader,
        "river.request.remove-header" => RequestRemoveHeaderKeyRegex,
    }

    responses: {
        "river.response.upsert-header" => ResponseUpsertHeader,
        "river.response.remove-header" => ResponseRemoveHeaderKeyRegex,
    }
}
