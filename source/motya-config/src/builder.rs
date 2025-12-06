
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use async_recursion::async_recursion;
use async_trait::async_trait;
use kdl::KdlDocument;
use miette::{Context, IntoDiagnostic, Result, miette};
use tokio::fs;

use crate::internal::{Config, ProxyConfig};
use crate::kdl::{
    includes::IncludesSection,
    connectors::ConnectorsSection,
    definitions::DefinitionsSection,
    file_server::FileServerSection,
    listeners::ListenersSection,
    rate_limiter::RateLimitSection,
    system_data::SystemDataSection,
    utils,
};
use crate::common_types::{
    bad::Bad, 
    definitions::DefinitionsTable, 
    file_server::FileServerConfig,
    section_parser::SectionParser,
    service::{ServiceSection, ServiceSectionParser},
};

/// Orchestrates the loading and composition of the configuration from multiple KDL files.
///
/// This loader implements a **Two-Pass Parsing** strategy to allow for cross-file references
/// and modular configuration (e.g., defining filters in one file and using them in another).
///
/// # Loading Process
///
/// 1. **File Discovery (Recursive)**:
///    Starts from the `entry_point` path and recursively resolves `include` directives
///    to build a flat list of unique KDL documents. Cycles and duplicate imports are handled.
///
/// 2. **Phase 1: Definitions & Plugins**:
///    Iterates through *all* loaded documents to collect and merge `definitions` blocks.
///    - Parses named filter chains and plugin definitions.
///
/// 3. **Phase 2: System & Services**:
///    Iterates through the documents again to build the concrete configuration:
///    - **System Data**: Extracted *only* from the entry point document.
///    - **Services**: Aggregated from *all* documents.
///      - During service parsing, anonymous chains (e.g., `use-chain { ... }`) are detected
///        and registered into the global definitions table with generated names.

#[async_trait]
pub trait FileConfigLoaderProvider {
    async fn load_entry_point(mut self, path: Option<PathBuf>, global_definitions: &mut DefinitionsTable) -> Result<Option<Config>>;
}

#[derive(Default, Clone)]
pub struct ConfigLoader {
    documents: Vec<KdlDocument>,
    visited_paths: HashSet<PathBuf>,
}

#[async_trait]
impl FileConfigLoaderProvider for ConfigLoader {
    async fn load_entry_point(mut self, path: Option<PathBuf>, global_definitions: &mut DefinitionsTable) -> Result<Option<Config>> {
        if let Some(path) = path {
            let root_path = std::fs::canonicalize(path)
                .into_diagnostic()
                .context("Failed to resolve entry point path")?;

            self.load_recursive(root_path).await?;

            Ok(Some(self.build_config(global_definitions).await?))
        }
        else {
            Ok(None)
        }
    }
}

impl ConfigLoader {
    
    #[async_recursion]
    async fn load_recursive(&mut self, path: PathBuf) -> Result<()> {
        
        if self.visited_paths.contains(&path) {
            tracing::debug!("Skipping already loaded file: {:?}", path);
            return Ok(());
        }
        self.visited_paths.insert(path.clone());

        tracing::info!("Loading config file: {:?}", path);
        
        let content = fs::read_to_string(&path)
            .await
            .into_diagnostic()
            .wrap_err_with(|| format!("Failed to read file: {:?}", path))?;

        let doc: KdlDocument = content
            .parse()
            .into_diagnostic()
            .wrap_err_with(|| format!("Failed to parse KDL: {:?}", path))?;

            
        let raw_includes = IncludesSection::new(&doc).parse_node(&doc)?;

        let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
        
        for path_str in raw_includes {
            let include_path = base_dir.join(path_str);
            
            let abs_path = if include_path.is_absolute() {
                include_path
            } else {
                fs::canonicalize(&include_path).await
                    .unwrap_or(include_path)
            };
            
            self.load_recursive(abs_path).await?;
        }

        self.documents.push(doc);

        Ok(())
    }

    
    async fn build_config(self, global_definitions: &mut DefinitionsTable) -> Result<Config> {
        if self.documents.is_empty() {
            return Err(miette!("No configuration documents loaded"));
        }

        let mut final_config = Config::default();

        // ---------------------------------------------------------
        // 1. System Data (Only from Entry Point / documents.last)
        // ---------------------------------------------------------
        let entry_doc = self.documents.last().expect("documents must not be empty");
        
        let sys_data = SystemDataSection::new(entry_doc).parse_node(entry_doc)?;
        
        final_config.threads_per_service = sys_data.threads_per_service;
        final_config.daemonize = sys_data.daemonize;
        final_config.upgrade_socket = sys_data.upgrade_socket;
        final_config.pid_file = sys_data.pid_file;


        // ---------------------------------------------------------
        // 2. Definitions Merge
        // ---------------------------------------------------------
        for doc in &self.documents {
            let defs = DefinitionsSection::new(doc).parse_node(doc)?;
            global_definitions.merge(defs)?;
        }


        // ---------------------------------------------------------
        // 3. Services Merge
        // ---------------------------------------------------------
        let mut service_names = HashSet::new();

        for doc in &self.documents {
            if doc.get("services").is_none() {
                continue;
            }

            let (proxies, file_servers) = extract_services(
                final_config.threads_per_service,
                doc,
                global_definitions
            )?;

            for p in &proxies {
                if !service_names.insert(p.name.clone()) {
                    return Err(miette!("Duplicate service name found: '{}'", p.name));
                }
            }
            for fs in &file_servers {
                if !service_names.insert(fs.name.clone()) {
                    return Err(miette!("Duplicate file-server name found: '{}'", fs.name));
                }
            }

            final_config.basic_proxies.extend(proxies);
            final_config.file_servers.extend(file_servers);
        }

        Ok(final_config)
    }
}

fn extract_services(
    threads_per_service: usize,
    doc: &KdlDocument,
    table: &mut DefinitionsTable
) -> miette::Result<(Vec<ProxyConfig>, Vec<FileServerConfig>)> {
    let service_node = utils::required_child_doc(doc, doc, "services")?;
    let services = utils::wildcard_argless_child_docs(doc, service_node)?;

    let proxy_node_set =
        HashSet::from(["listeners", "connectors", "path-control", "rate-limiting"]);
    let file_server_node_set = HashSet::from(["listeners", "file-server"]);

    let mut proxies = vec![];
    let mut file_servers = vec![];

    for (name, service) in services {
        // First, visit all of the children nodes, and make sure each child
        // node only appears once. This is used to detect duplicate sections
        let mut fingerprint_set: HashSet<&str> = HashSet::new();
        for ch in service.nodes() {
            let name = ch.name().value();
            let dupe = !fingerprint_set.insert(name);
            if dupe {
                return Err(Bad::docspan(format!("Duplicate section: '{name}'!"), doc, &ch.span()).into());
            }
        }

        // Now: what do we do with this node?
        if fingerprint_set.is_subset(&proxy_node_set) {
            // If the contained nodes are a strict subset of proxy node config fields,
            // then treat this section as a proxy node
            proxies.push(extract_service(threads_per_service, doc, name, service, table)?);
        } else if fingerprint_set.is_subset(&file_server_node_set) {
            // If the contained nodes are a strict subset of the file server config
            // fields, then treat this section as a file server node
            file_servers.push(FileServerSection::new(doc, name).parse_node(service)?);
        } else {
            // Otherwise, we're not sure what this node is supposed to be!
            //
            // Obtain the superset of ALL potential nodes, which is essentially
            // our configuration grammar.
            let superset: HashSet<&str> = proxy_node_set
                .union(&file_server_node_set)
                .cloned()
                .collect();

            // Then figure out what fields our fingerprint set contains that
            // is "novel", or basically fields we don't know about
            let what = fingerprint_set
                .difference(&superset)
                .copied()
                .collect::<Vec<&str>>()
                .join(", ");

            // Then inform the user about the reason for our discontent
            return Err(Bad::docspan(
                format!("Unknown configuration section(s): '{what}'"),
                doc,
                &service.span(),
            )
            .into());
        }
    }

    if proxies.is_empty() && file_servers.is_empty() {
        return Err(Bad::docspan("No services defined", doc, &service_node.span()).into());
    }

    Ok((proxies, file_servers))
}



/// Extracts a single service from the `services` block
fn extract_service(
    threads_per_service: usize,
    doc: &KdlDocument,
    name: &str,
    node: &KdlDocument,
    table: &mut DefinitionsTable
) -> miette::Result<ProxyConfig> {
    let config = ServiceSection::<_>::new(
        &ListenersSection::new(doc), 
        &ConnectorsSection::new(doc, table),
        &RateLimitSection::new(doc, threads_per_service), 
        name
    ).parse_node(node)?;

    table.extend_chain(config.connectors.anonymous_chains.clone());

    Ok(config)
}


#[cfg(test)]
mod tests {

    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;
    use fqdn::fqdn;
    #[tokio::test]
    async fn test_namespace_merge_across_files() {
        
        let dir = tempdir().unwrap();

        const DEF_ONE: &str = r#"
        definitions {
            modifiers {
                namespace "motya" {
                    namespace "inner" {
                        def name="one"
                    }
                }
            }
        }
        "#;

        const DEF_TWO: &str = r#"
        definitions {
            modifiers {
                namespace "motya" {
                    namespace "inner" {
                        def name="two"
                    }
                }
            }
        }
        "#;

        const MAIN_CONFIG: &str = r#"
        includes {
            include "./def1.kdl"
            include "./def2.kdl"
        }
        
        system {
            threads-per-service 1
        }

        services {
            TestService {
                listeners { "127.0.0.1:8080" }
                connectors {
                    return code="200" response="OK"
                }
            }
        }
        "#;

        let def1_path = dir.path().join("def1.kdl");
        File::create(&def1_path).unwrap()
            .write_all(DEF_ONE.as_bytes()).unwrap();

        let def2_path = dir.path().join("def2.kdl");
        File::create(&def2_path).unwrap()
            .write_all(DEF_TWO.as_bytes()).unwrap();

        let main_path = dir.path().join("main.kdl");
        File::create(&main_path).unwrap()
            .write_all(MAIN_CONFIG.as_bytes()).unwrap();

        let loader = ConfigLoader::default();

        let mut def_table = DefinitionsTable::new_with_global();

        loader.load_entry_point(Some(main_path), &mut def_table).await.expect("Config should load successfully");

        assert!(
            def_table.get_available_filters().contains(&fqdn!("motya.inner.one")),
            "FQDN 'motya.inner.one' is missing in global definitions"
        );
        assert!(
            def_table.get_available_filters().contains(&fqdn!("motya.inner.two")),
            "FQDN 'motya.inner.two' is missing in global definitions"
        );
    }

    #[tokio::test]
    async fn test_duplicate_plugin_definition_across_files() {
        let dir = tempdir().unwrap();

        const SHARED_PLUGIN: &str = r#"
        definitions {
            plugins {
                plugin {
                    name "duplicate-plugin"
                    load path="./assets/filter.wasm"
                }
            }
        }
        "#;

        const MAIN_CONFIG: &str = r#"
        includes {
            include "./def1.kdl"
            include "./def2.kdl"
        }
        
        system {
            threads-per-service 1
        }

        services {
            TestService {
                listeners { "127.0.0.1:8080" }
                connectors {
                    use-chain "test-chain"
                    return code="200" response="OK"
                }
            }
        }
        "#;

        let def1_path = dir.path().join("def1.kdl");
        File::create(&def1_path).unwrap()
            .write_all(SHARED_PLUGIN.as_bytes()).unwrap();

        let def2_path = dir.path().join("def2.kdl");
        File::create(&def2_path).unwrap()
            .write_all(SHARED_PLUGIN.as_bytes()).unwrap();

        let main_path = dir.path().join("main.kdl");
        File::create(&main_path).unwrap()
            .write_all(MAIN_CONFIG.as_bytes()).unwrap();

        let loader = ConfigLoader::default();

        let mut def_table = DefinitionsTable::new_with_global();

        let result = loader.load_entry_point(Some(main_path), &mut def_table).await;

        assert!(result.is_err());

        let err_msg = result.unwrap_err().to_string();

        crate::assert_err_contains!(err_msg, "Duplicate plugin definition across files: 'duplicate-plugin'");
    }

    #[tokio::test]
    async fn test_duplicate_chain_definition_across_files() {
        let dir = tempdir().unwrap();

        const SHARED_DEF: &str = r#"
            definitions {
                modifiers {
                    chain-filters "conflict-chain" { }
                }
            }
        "#;

        const MAIN_CONFIG: &str = r#"
            includes {
                include "./def1.kdl"
                include "./def2.kdl"
            }
            
            system {
                threads-per-service 1
            }

            services { 
                TestService {
                    listeners { "127.0.0.1:8080" }
                    connectors {
                        use-chain "test-chain"
                        return code="200" response="OK"
                    }
                }
            }
        "#;
        
    
        let def1_path = dir.path().join("def1.kdl");
        File::create(&def1_path).unwrap()
            .write_all(SHARED_DEF.as_bytes()).unwrap();
        
        
        let def2_path = dir.path().join("def2.kdl");
        File::create(&def2_path).unwrap()
            .write_all(SHARED_DEF.as_bytes()).unwrap();

            
        let main_path = dir.path().join("main.kdl");
        File::create(&main_path).unwrap()
            .write_all(MAIN_CONFIG.as_bytes()).unwrap();

            
        let loader = ConfigLoader::default();

        let mut def_table = DefinitionsTable::new_with_global();

        
        let result = loader.load_entry_point(Some(main_path), &mut def_table).await;

        let err_msg = result.unwrap_err().to_string();
        crate::assert_err_contains!(err_msg, "Duplicate chain definition across files: 'conflict-chain'");
    }

    #[tokio::test]
    async fn test_include_logic() {
        let dir = tempdir().unwrap();
        
        const DEFINITIONS_FILE: &str = r#"
            definitions {
                modifiers {
                    chain-filters "test-chain" { }
                }
            }
        "#;

        let def_path = dir.path().join("definitions.kdl");
        let mut def_file = File::create(&def_path).unwrap();
        writeln!(def_file, "{}", DEFINITIONS_FILE).unwrap();

        let main_path = dir.path().join("main.kdl");
        let mut main_file = File::create(&main_path).unwrap();
        
        const MAIN_FILE: &str = r#"
            includes {
                include "./definitions.kdl"
            }
            
            system {
                threads-per-service 2
            }

            services {
                TestService {
                    listeners { "127.0.0.1:8080" }
                    connectors {
                        use-chain "test-chain"
                        return code="200" response="OK"
                    }
                }
            }
        "#;
        
        writeln!(main_file, "{MAIN_FILE}").unwrap();

        let loader = ConfigLoader::default();
        let mut def_table = DefinitionsTable::new_with_global();
        
        let config = loader.load_entry_point(Some(main_path), &mut def_table).await.expect("Failed to load config").unwrap();

        assert_eq!(config.threads_per_service, 2);
        assert_eq!(config.basic_proxies.len(), 1);
        
    }
}
