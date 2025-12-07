#[macro_export]
macro_rules! define_builtin_filters {
    ($callback:ident) => {
        $callback! {
            actions: {
                "motya.filters.block-cidr-range" => CidrRangeFilter,
            }

            requests: {
                "motya.request.upsert-header" => RequestUpsertHeader,
                "motya.request.remove-header" => RequestRemoveHeaderKeyRegex,
                "motya.request.strip-prefix" => StripPrefix,
                "motya.request.rewrite-path" => RewritePathRegex,
            }

            responses: {
                "motya.response.upsert-header" => ResponseUpsertHeader,
                "motya.response.remove-header" => ResponseRemoveHeaderKeyRegex,
            }
        }
    };
}

macro_rules! impl_definitions_table {
    (
        $(
            $section:ident: {
                $($key:literal => $ignore_type:ty),* $(,)?
            }
        )*
    ) => {
        use crate::common_types::definitions_table::DefinitionsTable;

        pub fn load_definitions_table() -> DefinitionsTable {
            let mut definitions = DefinitionsTable::default();

            $($(
                let key = fqdn::fqdn!($key);
                definitions.insert_filter(key);
            )*)*

            definitions
        }
    };
}

define_builtin_filters!(impl_definitions_table);
