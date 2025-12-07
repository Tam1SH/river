use std::{collections::HashMap, net::SocketAddr};

use kdl::{KdlDocument, KdlEntry, KdlNode};

use crate::{
    common_types::{
        bad::Bad,
        listeners::{ListenerConfig, ListenerKind, Listeners, TlsConfig},
        section_parser::SectionParser,
    },
    kdl::utils::{self, HashMapValidationExt},
};

pub struct ListenersSection<'a> {
    doc: &'a KdlDocument,
}

impl SectionParser<KdlDocument, Listeners> for ListenersSection<'_> {
    fn parse_node(&self, node: &KdlDocument) -> miette::Result<Listeners> {
        let listener_node = utils::required_child_doc(self.doc, node, "listeners")?;
        let listeners = utils::data_nodes(self.doc, listener_node)?;
        if listeners.is_empty() {
            return Err(Bad::docspan(
                "nonzero listeners required",
                self.doc,
                &listener_node.span(),
            )
            .into());
        }

        let mut list_cfgs = vec![];
        for (node, name, args) in listeners {
            let listener = Self::extract_listener(self.doc, node, name, args)?;
            list_cfgs.push(listener);
        }

        Ok(Listeners { list_cfgs })
    }
}

impl<'a> ListenersSection<'a> {
    pub fn new(doc: &'a KdlDocument) -> Self {
        Self { doc }
    }

    fn extract_listener(
        doc: &KdlDocument,
        node: &KdlNode,
        name: &str,
        args: &[KdlEntry],
    ) -> miette::Result<ListenerConfig> {
        // Is this a bindable name?
        if name.parse::<SocketAddr>().is_ok() {
            let args = utils::str_value_args(doc, args)?
                .into_iter()
                .collect::<HashMap<&str, &KdlEntry>>()
                .ensure_only_keys(&["cert-path", "key-path", "offer-h2"], doc, node)?;

            // Cool: do we have reasonable args for this?
            let cert_path = utils::map_ensure_str(doc, args.get("cert-path").copied())?;
            let key_path = utils::map_ensure_str(doc, args.get("key-path").copied())?;
            let offer_h2 = utils::map_ensure_bool(doc, args.get("offer-h2").copied())?;

            match (cert_path, key_path, offer_h2) {
                // No config? No problem!
                (None, None, None) => Ok(ListenerConfig {
                    source: ListenerKind::Tcp {
                        addr: name.to_string(),
                        tls: None,
                        offer_h2: false,
                    },
                }),
                // We must have both of cert-path and key-path if both are present
                // ignore "offer-h2" if this is incorrect
                (None, Some(_), _) | (Some(_), None, _) => {
                    Err(Bad::docspan(
                        "'cert-path' and 'key-path' must either BOTH be present, or NEITHER should be present",
                        doc,
                        &node.span(),
                    )
                    .into())
                }
                // We can't offer H2 if we don't have TLS (at least for now, unless we
                // expose H2C settings in pingora)
                (None, None, Some(_)) => {
                    Err(Bad::docspan(
                        "'offer-h2' requires TLS, specify 'cert-path' and 'key-path'",
                        doc,
                        &node.span(),
                    )
                    .into())
                }
                (Some(cpath), Some(kpath), offer_h2) => Ok(ListenerConfig {
                    source: ListenerKind::Tcp {
                        addr: name.to_string(),
                        tls: Some(TlsConfig {
                            cert_path: cpath.into(),
                            key_path: kpath.into(),
                        }),
                        // Default to enabling H2 if unspecified
                        offer_h2: offer_h2.unwrap_or(true),
                    },
                }),
            }
        }
        // else if let Ok(pb) = name.parse::<PathBuf>() {
        //     // TODO: Should we check that this path exists? Otherwise it seems to always match
        //     Ok(ListenerConfig {
        //         source: ListenerKind::Uds(pb),
        //     })
        // }
        else {
            Err(Bad::docspan(
                format!("'{name}' is not a socketaddr or path?"),
                doc,
                &node.span(),
            )
            .into())
        }
    }
}
