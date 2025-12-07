use std::collections::HashMap;

use kdl::KdlDocument;

use crate::{
    common_types::{file_server::FileServerConfig, section_parser::SectionParser},
    kdl::{listeners::ListenersSection, utils},
};

pub struct FileServerSection<'a> {
    doc: &'a KdlDocument,
    name: &'a str,
}

impl SectionParser<KdlDocument, FileServerConfig> for FileServerSection<'_> {
    fn parse_node(&self, node: &KdlDocument) -> miette::Result<FileServerConfig> {
        self.extract_file_server(node)
    }
}

impl<'a> FileServerSection<'a> {
    pub fn new(doc: &'a KdlDocument, name: &'a str) -> Self {
        Self { doc, name }
    }

    /// Extracts a single file server from the `services` block
    fn extract_file_server(&self, node: &KdlDocument) -> miette::Result<FileServerConfig> {
        // Listeners
        //
        let listeners = ListenersSection::new(self.doc).parse_node(node)?;
        // Base Path
        //
        let fs_node = utils::required_child_doc(self.doc, node, "file-server")?;
        let data_nodes = utils::data_nodes(self.doc, fs_node)?;
        let mut map = HashMap::new();
        for (node, name, args) in data_nodes {
            map.insert(name, (node, args));
        }

        let base_path = if let Some((bpnode, bpargs)) = map.get("base-path") {
            let val = utils::extract_one_str_arg(self.doc, bpnode, "base-path", bpargs, |a| {
                Some(a.to_string())
            })?;
            Some(val.into())
        } else {
            None
        };

        Ok(FileServerConfig {
            name: self.name.to_string(),
            listeners,
            base_path,
        })
    }
}
