use std::path::PathBuf;
use kdl::KdlDocument;
use crate::{
    common_types::{
        section_parser::SectionParser, bad::{Bad, OptExtParse}, system_data::SystemData
    },
    kdl::utils,
};

pub struct SystemDataSection<'a> {
    doc: &'a KdlDocument,
}

impl SectionParser<KdlDocument, SystemData> for SystemDataSection<'_> {
    fn parse_node(&self, _: &KdlDocument) -> miette::Result<SystemData> {
        self.extract_system_data()    
    }
}

impl<'a> SystemDataSection<'a> {

    pub fn new(doc: &'a KdlDocument) -> Self { Self { doc } }

    
    // system { threads-per-service N }
    fn extract_system_data(&self) -> miette::Result<SystemData> {
        // Get the top level system doc
        
        let Some(sys) = utils::optional_child_doc(self.doc, self.doc, "system") else {
            
            return Ok(SystemData::default());
        };
        let tps = self.extract_threads_per_service(sys)?;

        let daemonize = if let Some(n) = sys.get("daemonize") {
            utils::extract_one_bool_arg(self.doc, n, "daemonize", n.entries())?
        } else {
            false
        };

        let upgrade_socket = if let Some(n) = sys.get("upgrade-socket") {
            let x = utils::extract_one_str_arg(self.doc, n, "upgrade-socket", n.entries(), |s| {
                Some(PathBuf::from(s))
            })?;
            Some(x)
        } else {
            None
        };

        let pid_file = if let Some(n) = sys.get("pid-file") {
            let x = utils::extract_one_str_arg(self.doc, n, "pid-file", n.entries(), |s| {
                Some(PathBuf::from(s))
            })?;
            Some(x)
        } else {
            None
        };

        Ok(SystemData {
            threads_per_service: tps,
            daemonize,
            upgrade_socket,
            pid_file,
        })
    }

    fn extract_threads_per_service(&self, sys: &KdlDocument) -> miette::Result<usize> {
        let Some(tps) = sys.get("threads-per-service") else {
            return Ok(8);
        };

        let [tps_node] = tps.entries() else {
            return Err(Bad::docspan(
                "system > threads-per-service should have exactly one entry",
                self.doc,
                &tps.span(),
            )
            .into());
        };

        let val = tps_node.value().as_integer().or_bail(
            "system > threads-per-service should be an integer",
            self.doc,
            &tps_node.span(),
        )?;
        val.try_into().ok().or_bail(
            "system > threads-per-service should fit in a usize",
            self.doc,
            &tps_node.span(),
        )
    }


}
