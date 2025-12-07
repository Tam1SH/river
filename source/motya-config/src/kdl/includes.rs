use crate::{
    common_types::{bad::Bad, section_parser::SectionParser},
    kdl::utils,
};
use kdl::KdlDocument;

pub struct IncludesSection<'a> {
    doc: &'a KdlDocument,
}

impl SectionParser<KdlDocument, Vec<String>> for IncludesSection<'_> {
    fn parse_node(&self, _node: &KdlDocument) -> miette::Result<Vec<String>> {
        self.extract_includes()
    }
}

impl<'a> IncludesSection<'a> {
    pub fn new(doc: &'a KdlDocument) -> Self {
        Self { doc }
    }

    fn extract_includes(&self) -> miette::Result<Vec<String>> {
        let mut paths = Vec::new();

        if let Some(inc_block) = utils::optional_child_doc(self.doc, self.doc, "includes") {
            let nodes = utils::data_nodes(self.doc, inc_block)?;

            for (node, name, args) in nodes {
                if name == "include" {
                    let path_str =
                        utils::extract_one_str_arg(self.doc, node, "include", args, |s| {
                            Some(s.to_string())
                        })?;
                    paths.push(path_str);
                } else {
                    return Err(Bad::docspan(
                        format!("Unknown directive '{name}' inside includes block. Only 'include' is allowed."),
                        self.doc,
                        &node.span()
                    ).into());
                }
            }
        }

        Ok(paths)
    }
}
