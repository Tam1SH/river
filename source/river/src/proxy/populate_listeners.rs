use pingora::listeners::tls::TlsSettings;

use crate::config::common_types::listeners::{ListenerKind, Listeners};



pub fn populate_listners<T>(
    listeners: &Listeners,
    service: &mut pingora_core::services::listening::Service<T>,
) {
    for list_cfg in listeners.list_cfgs.iter() {
        // NOTE: See https://github.com/cloudflare/pingora/issues/182 for tracking "paths aren't
        // always UTF-8 strings".
        //
        // See also https://github.com/cloudflare/pingora/issues/183 for tracking "ip addrs shouldn't
        // be strings"
        match &list_cfg.source {
            ListenerKind::Tcp {
                addr,
                tls: Some(tls_cfg),
                offer_h2,
            } => {
                let cert_path = tls_cfg
                    .cert_path
                    .to_str()
                    .expect("cert path should be utf8");
                let key_path = tls_cfg.key_path.to_str().expect("key path should be utf8");

                // TODO: Make conditional!
                let mut settings = TlsSettings::intermediate(cert_path, key_path)
                    .expect("adding TLS listener shouldn't fail");
                if *offer_h2 {
                    settings.enable_h2();
                }

                service.add_tls_with_settings(&addr, None, settings);
            }
            ListenerKind::Tcp {
                addr,
                tls: None,
                offer_h2,
            } => {
                if *offer_h2 {
                    panic!("Unsupported configuration: {addr:?} configured without TLS, but H2 enabled which requires TLS");
                }
                service.add_tcp(&addr);
            }
            ListenerKind::Uds(path) => {
                let path = path.to_str().unwrap();
                service.add_uds(path, None); // todo
            }
        }
    }
}