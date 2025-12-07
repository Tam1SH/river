use http::StatusCode;
use miette::{miette, Context, IntoDiagnostic, Result};
use reqwest::Client;
use std::time::Duration;

use motya_config::common_types::definitions::PluginSource;

pub struct PluginLoader;

impl PluginLoader {
    fn client() -> Result<Client> {
        Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent("motya-proxy/0.1")
            .build()
            .into_diagnostic()
    }

    pub async fn check_availability(source: &PluginSource) -> Result<()> {
        match source {
            PluginSource::File(path) => {
                if !path.exists() {
                    return Err(miette!("Plugin file not found: {:?}", path));
                }
                if !path.is_file() {
                    return Err(miette!("Path is not a file: {:?}", path));
                }
                Ok(())
            }
            PluginSource::Url(url) => {
                let client = Self::client()?;

                let response = client
                    .head(url)
                    .send()
                    .await
                    .into_diagnostic()
                    .wrap_err_with(|| format!("Failed to send HEAD request to {}", url))?;

                if response.status() != StatusCode::OK {
                    return Err(miette!(
                        "Plugin URL {} is unreachable. Status: {}",
                        url,
                        response.status()
                    ));
                }

                if let Some(len) = response.headers().get(reqwest::header::CONTENT_LENGTH) {
                    if let Ok(s) = len.to_str() {
                        if let Ok(bytes) = s.parse::<u64>() {
                            if bytes > 50 * 1024 * 1024 {
                                return Err(miette!("Plugin is too large: {} bytes", bytes));
                            }
                        }
                    }
                }

                Ok(())
            }
        }
    }

    pub async fn fetch_bytes(source: &PluginSource) -> Result<Vec<u8>> {
        match source {
            PluginSource::File(path) => tokio::fs::read(path)
                .await
                .into_diagnostic()
                .wrap_err_with(|| format!("Failed to read file {:?}", path)),
            PluginSource::Url(url) => {
                let client = Self::client()?;
                let response = client
                    .get(url)
                    .send()
                    .await
                    .into_diagnostic()
                    .wrap_err_with(|| format!("Failed to GET {}", url))?;

                let bytes = response
                    .bytes()
                    .await
                    .into_diagnostic()
                    .wrap_err("Failed to read response body")?;

                Ok(bytes.to_vec())
            }
        }
    }
}
