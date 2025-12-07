// use std::{
//     collections::{HashMap, HashSet},
//     hash::Hash,
// };

// use fqdn::FQDN;

// use motya_config::common_types::{
//     definitions::{FilterChain, PluginDefinition},
//     definitions_table::DefinitionsTable,
// };

// #[derive(Debug, Clone, PartialEq)]
// pub enum MapDiffState<T> {
//     Added(T),
//     Deleted(T),
//     Modified { old: T, new: T },
//     Unchanged(T),
// }

// #[derive(Debug, Clone, PartialEq)]
// pub enum SetDiffState {
//     Added,
//     Deleted,
//     Unchanged,
// }

// #[derive(Debug, Clone)]
// pub struct DefinitionsTableDiff {
//     pub filters: HashMap<FQDN, SetDiffState>,
//     pub chains: HashMap<String, MapDiffState<FilterChain>>,
//     pub plugins: HashMap<FQDN, MapDiffState<PluginDefinition>>,
// }

// impl DefinitionsTableDiff {
//     pub fn diff(old: &DefinitionsTable, new: &DefinitionsTable) -> DefinitionsTableDiff {
//         DefinitionsTableDiff {
//             filters: diff_set(old.get_available_filters(), new.get_available_filters()),
//             chains: diff_map(old.get_chains(), new.get_chains()),
//             plugins: diff_map(old.get_plugins(), new.get_plugins()),
//         }
//     }
// }

// fn diff_set<T>(old: &HashSet<T>, new: &HashSet<T>) -> HashMap<T, SetDiffState>
// where
//     T: Eq + Hash + Clone,
// {
//     let mut diff = HashMap::new();

//     for val in new {
//         if old.contains(val) {
//             diff.insert(val.clone(), SetDiffState::Unchanged);
//         } else {
//             diff.insert(val.clone(), SetDiffState::Added);
//         }
//     }

//     for val in old {
//         if !new.contains(val) {
//             diff.insert(val.clone(), SetDiffState::Deleted);
//         }
//     }

//     diff
// }

// fn diff_map<K, V>(old: &HashMap<K, V>, new: &HashMap<K, V>) -> HashMap<K, MapDiffState<V>>
// where
//     K: Eq + Hash + Clone,
//     V: PartialEq + Clone,
// {
//     let mut diff = HashMap::new();

//     for (key, new_val) in new {
//         match old.get(key) {
//             Some(old_val) => {
//                 if old_val == new_val {
//                     diff.insert(key.clone(), MapDiffState::Unchanged(new_val.clone()));
//                 } else {
//                     diff.insert(
//                         key.clone(),
//                         MapDiffState::Modified {
//                             old: old_val.clone(),
//                             new: new_val.clone(),
//                         },
//                     );
//                 }
//             }
//             None => {
//                 diff.insert(key.clone(), MapDiffState::Added(new_val.clone()));
//             }
//         }
//     }

//     for (key, old_val) in old {
//         if !new.contains_key(key) {
//             diff.insert(key.clone(), MapDiffState::Deleted(old_val.clone()));
//         }
//     }

//     diff
// }

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use fqdn::fqdn;
//     use motya_config::common_types::{
//         definitions::ConfiguredFilter, definitions_table::DefinitionsTable,
//     };

//     fn cfg_filter(name: FQDN, args: &[(&str, &str)]) -> ConfiguredFilter {
//         let mut map = HashMap::new();
//         for (k, v) in args {
//             map.insert(k.to_string(), v.to_string());
//         }
//         ConfiguredFilter { name, args: map }
//     }

//     fn chain(filters: Vec<ConfiguredFilter>) -> FilterChain {
//         FilterChain { filters }
//     }

//     #[test]
//     fn test_definitions_diff_deep_compare() {
//         let mut old = DefinitionsTable::default();
//         let mut new = DefinitionsTable::default();

//         old.insert_chain(
//             "static",
//             chain(vec![cfg_filter(fqdn!("rate_limit"), &[("rate", "10")])]),
//         );

//         old.insert_chain(
//             "api",
//             chain(vec![
//                 cfg_filter(fqdn!("auth"), &[]),
//                 cfg_filter(fqdn!("logger"), &[("verbose", "false")]),
//             ]),
//         );

//         old.insert_chain("legacy", chain(vec![cfg_filter(fqdn!("old"), &[])]));

//         new.insert_chain(
//             "static",
//             chain(vec![cfg_filter(fqdn!("rate_limit"), &[("rate", "10")])]),
//         );

//         new.insert_chain(
//             "api",
//             chain(vec![
//                 cfg_filter(fqdn!("auth"), &[]),
//                 cfg_filter(fqdn!("logger"), &[("verbose", "true")]),
//             ]),
//         );

//         new.insert_chain("new", chain(vec![cfg_filter(fqdn!("cors"), &[])]));

//         // act.
//         let diff = DefinitionsTableDiff::diff(&old, &new);

//         match diff.chains.get("static") {
//             Some(MapDiffState::Unchanged(chain)) => {
//                 assert_eq!(chain.filters.len(), 1);
//                 assert_eq!(chain.filters[0].name, fqdn!("rate_limit"));
//             }
//             _ => panic!("Expected 'static' chain to be Unchanged"),
//         }

//         match diff.chains.get("api") {
//             Some(MapDiffState::Modified { old, new }) => {
//                 let old_arg = old.filters[1].args.get("verbose").unwrap();
//                 let new_arg = new.filters[1].args.get("verbose").unwrap();
//                 assert_eq!(old_arg, "false");
//                 assert_eq!(new_arg, "true");
//             }
//             _ => panic!("Expected 'api' chain to be Modified due to args change"),
//         }

//         assert!(matches!(
//             diff.chains.get("legacy"),
//             Some(MapDiffState::Deleted(_))
//         ));
//         assert!(matches!(
//             diff.chains.get("new"),
//             Some(MapDiffState::Added(_))
//         ));
//     }
// }
