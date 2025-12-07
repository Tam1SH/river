use std::{collections::HashMap, convert::Infallible, path::PathBuf, time::Duration};

use futures_util::future::try_join_all;
use miette::IntoDiagnostic;
use notify::{Event, RecursiveMode, Watcher};
use tokio::sync::mpsc;

use crate::proxy::{
    upstream_factory::UpstreamFactory, upstream_router::UpstreamRouter, SharedProxyState,
};
use motya_config::{
    builder::{ConfigLoader, FileConfigLoaderProvider},
    common_types::definitions_table::DefinitionsTable,
    internal::{Config, ProxyConfig},
};

pub struct ConfigWatcher<TConfigLoader: FileConfigLoaderProvider + Clone = ConfigLoader> {
    config: Config,
    table: DefinitionsTable,
    active_proxies: HashMap<String, SharedProxyState>,
    watch_entry_path: PathBuf,
    upstream_factory: UpstreamFactory,
    config_loader: TConfigLoader,
}

impl<T: FileConfigLoaderProvider + Clone> ConfigWatcher<T> {
    pub fn new(
        config: Config,
        table: DefinitionsTable,
        watch_entry_path: PathBuf,
        upstream_factory: UpstreamFactory,
        config_loader: T,
    ) -> Self {
        Self {
            config,
            table,
            watch_entry_path,
            upstream_factory,
            config_loader,
            active_proxies: HashMap::default(),
        }
    }

    pub fn insert_proxy_state(&mut self, name: String, state: SharedProxyState) {
        self.active_proxies.insert(name, state);
    }

    pub async fn watch(&mut self) -> Result<Infallible, Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!("Starting watcher on: {:?}", &self.watch_entry_path);

        let (tx, mut rx) = mpsc::channel(100);

        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                if event.kind.is_modify() || event.kind.is_create() || event.kind.is_remove() {
                    let _ = tx.blocking_send(event);
                }
            }
        })?;

        watcher.watch(&self.watch_entry_path, RecursiveMode::Recursive)?;

        loop {
            if let Some(_event) = rx.recv().await {
                tokio::time::sleep(Duration::from_millis(100)).await;

                while rx.try_recv().is_ok() {}

                match self.reload().await {
                    Ok(_) => {}
                    Err(err) => tracing::error!("fail on reload: {err}"),
                }
            }
        }
    }

    async fn reload(&mut self) -> miette::Result<()> {
        tracing::info!("Reloading configuration...");

        let mut new_definitions = DefinitionsTable::new_with_global();

        match self
            .config_loader
            .clone()
            .load_entry_point(Some(self.watch_entry_path.clone()), &mut new_definitions)
            .await
        {
            Ok(Some(cfg)) => {
                self.table = new_definitions;

                let old_proxies: HashMap<&String, &ProxyConfig> = self
                    .config
                    .basic_proxies
                    .iter()
                    .map(|p| (&p.name, p))
                    .collect();

                let new_proxies: HashMap<&String, &ProxyConfig> =
                    cfg.basic_proxies.iter().map(|p| (&p.name, p)).collect();

                for (name, new) in new_proxies.iter() {
                    if let Some(old) = old_proxies.get(name) {
                        if old.connectors != new.connectors {
                            if let Some(active_config) = self.active_proxies.get(*name) {
                                println!("Connectors changed for proxy '{}'", new.name);
                                let upstreams = try_join_all(
                                    new.connectors
                                        .upstreams
                                        .clone()
                                        .into_iter()
                                        .map(|cfg| self.upstream_factory.create_context(cfg))
                                        .collect::<Vec<_>>(),
                                )
                                .await?;

                                let router = UpstreamRouter::build(upstreams).into_diagnostic()?;

                                active_config.swap(router.into());
                            }
                            // logic...
                        }
                    } else {
                        // println!("New proxy detected: '{}'", new.name);
                    }
                }
            }
            Ok(None) => {
                tracing::warn!("Failed to load config: invariant violated: path not exist. Keeping old configuration.");
            }
            Err(e) => {
                tracing::warn!("Failed to reload config: {}. Keeping old configuration.", e);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use http::{uri::PathAndQuery, StatusCode};
    use miette::Result;
    use tempfile::env::temp_dir;
    use tokio::sync::Mutex;

    use super::*;
    use crate::proxy::{
        filters::{chain_resolver::ChainResolver, registry::FilterRegistry},
        ArcSwap,
    };
    use motya_config::common_types::{
        connectors::{Connectors, UpstreamConfig, UpstreamContextConfig},
        definitions_table::DefinitionsTable,
        listeners::Listeners,
        simple_response_type::SimpleResponseConfig,
    };

    #[derive(Clone)]
    struct MockConfigLoader {
        pub config_to_return: Arc<Mutex<Option<Config>>>,
    }

    impl MockConfigLoader {
        fn new(cfg: Config) -> Self {
            Self {
                config_to_return: Arc::new(Mutex::new(Some(cfg))),
            }
        }
    }

    #[async_trait]
    impl FileConfigLoaderProvider for MockConfigLoader {
        async fn load_entry_point(
            mut self,
            _path: Option<PathBuf>,
            _defs: &mut DefinitionsTable,
        ) -> Result<Option<Config>> {
            let cfg = self.config_to_return.lock().await.clone();
            Ok(cfg)
        }
    }

    #[tokio::test]
    async fn test_watcher_updates_proxies_using_mock() {
        let new_proxy_config = Config {
            basic_proxies: vec![ProxyConfig {
                listeners: Listeners { list_cfgs: vec![] },
                connectors: Connectors {
                    anonymous_definitions: Default::default(),
                    upstreams: vec![UpstreamContextConfig {
                        chains: vec![],
                        lb_options: Default::default(),
                        upstream: UpstreamConfig::Static(SimpleResponseConfig {
                            http_code: StatusCode::OK,
                            response_body: "ver 1".to_string(),
                            prefix_path: PathAndQuery::from_static("/"),
                        }),
                    }],
                },
                name: "Test".to_string(),
            }],
            ..Config::default()
        };

        let mock_loader = MockConfigLoader::new(new_proxy_config.clone());
        let table = DefinitionsTable::default();
        let registry = Arc::new(Mutex::new(FilterRegistry::default()));
        let resolver = ChainResolver::new(table.clone(), registry.clone())
            .await
            .unwrap();
        let factory = UpstreamFactory::new(resolver);

        let mut watcher = ConfigWatcher::new(
            new_proxy_config.clone(),
            table.clone(),
            temp_dir(),
            factory.clone(),
            mock_loader.clone(),
        );

        let upstream = factory
            .create_context(new_proxy_config.basic_proxies[0].connectors.upstreams[0].clone())
            .await
            .unwrap();

        let tracked_router = Arc::new(ArcSwap::from_pointee(
            UpstreamRouter::build(vec![upstream]).unwrap(),
        ));

        watcher.insert_proxy_state(
            new_proxy_config.basic_proxies[0].name.clone(),
            tracked_router.clone(),
        );

        //nothing happen.
        watcher.reload().await.expect("Reload failed");

        let router = tracked_router.load();
        let first_version = router.get_upstream_by_path("/").unwrap();
        let UpstreamConfig::Static(response) = &first_version.upstream else {
            unreachable!()
        };

        assert_eq!(response.response_body, "ver 1");

        let mut rewrited_config = mock_loader.config_to_return.lock().await;
        let not_empty_config = rewrited_config.as_mut().unwrap();
        not_empty_config.basic_proxies[0].connectors.upstreams[0].upstream =
            UpstreamConfig::Static(SimpleResponseConfig {
                http_code: StatusCode::OK,
                response_body: "ver 2".to_string(),
                prefix_path: PathAndQuery::from_static("/"),
            });

        drop(rewrited_config);

        //switch response
        watcher.reload().await.expect("Reload failed");

        let router = tracked_router.load();
        let second_version = router.get_upstream_by_path("/").unwrap();
        let UpstreamConfig::Static(response) = &second_version.upstream else {
            unreachable!()
        };

        assert_eq!(response.response_body, "ver 2");
    }
}
