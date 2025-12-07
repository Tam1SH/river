use std::collections::HashSet;

use kdl::KdlDocument;

use crate::{
    common_types::{
        bad::Bad, definitions_table::DefinitionsTable, file_server::FileServerConfig,
        section_parser::SectionParser, services::ServicesConfig,
    },
    internal::ProxyConfig,
    kdl::{
        connectors::ConnectorsSection, file_server::FileServerSection, listeners::ListenersSection,
        utils,
    },
};

#[derive(Debug)]
pub enum ServiceConfig {
    Proxy(ProxyConfig),
    FileServer(FileServerConfig),
}

pub struct ServicesSection<'a> {
    global_definitions: &'a DefinitionsTable,
}

impl SectionParser<KdlDocument, ServicesConfig> for ServicesSection<'_> {
    fn parse_node(&self, root: &KdlDocument) -> miette::Result<ServicesConfig> {
        self.parse(root)
    }
}

impl<'a> ServicesSection<'a> {
    pub fn new(global_definitions: &'a DefinitionsTable) -> Self {
        Self { global_definitions }
    }

    pub fn parse(&self, root: &KdlDocument) -> miette::Result<ServicesConfig> {
        let mut proxies: Vec<ProxyConfig> = vec![];
        let mut file_servers: Vec<FileServerConfig> = vec![];
        let services_node = utils::required_child_doc(root, root, "services")?;

        for (name, service_node) in utils::wildcard_argless_child_docs(root, services_node)? {
            match self.parse_service(name, service_node, root)? {
                ServiceConfig::FileServer(fs) => file_servers.push(fs),
                ServiceConfig::Proxy(proxy) => proxies.push(proxy),
            }
        }

        Ok(ServicesConfig {
            proxies,
            file_servers,
        })
    }

    fn parse_service(
        &self,
        name: &str,
        node: &KdlDocument,
        root: &KdlDocument,
    ) -> miette::Result<ServiceConfig> {
        let node_names: HashSet<&str> = node.nodes().iter().map(|n| n.name().value()).collect();

        if node_names.is_subset(&HashSet::from(["listeners", "connectors"])) {
            Ok(ServiceConfig::Proxy(self.parse_proxy(name, node, root)?))
        } else if node_names.is_subset(&HashSet::from(["listeners", "file-server"])) {
            Ok(ServiceConfig::FileServer(
                self.parse_file_server(name, node, root)?,
            ))
        } else {
            Err(Bad::docspan(
                format!("Unknown service type for '{}'", name),
                root,
                &node.span(),
            )
            .into())
        }
    }

    fn parse_proxy(
        &self,
        name: &str,
        node: &KdlDocument,
        root: &KdlDocument,
    ) -> miette::Result<ProxyConfig> {
        let listeners = ListenersSection::new(root).parse_node(node)?;

        let connectors = ConnectorsSection::new(root, self.global_definitions).parse_node(node)?;

        Ok(ProxyConfig {
            name: name.to_string(),
            listeners,
            connectors,
        })
    }

    fn parse_file_server(
        &self,
        name: &str,
        node: &KdlDocument,
        root: &KdlDocument,
    ) -> miette::Result<FileServerConfig> {
        FileServerSection::new(root, name).parse_node(node)
    }
}
