use crate::{
    common_types::{connectors::Connectors, listeners::Listeners, section_parser::SectionParser},
    internal::ProxyConfig,
};

pub struct ServiceSection<'a, T> {
    listeners: &'a dyn SectionParser<T, Listeners>,
    connectors: &'a dyn SectionParser<T, Connectors>,
    name: &'a str,
}

pub trait ServiceSectionParser<T> {
    fn parse_node(&self, node: &T) -> miette::Result<ProxyConfig>;
}

impl<'a, T> ServiceSection<'a, T> {
    pub fn new(
        listeners: &'a dyn SectionParser<T, Listeners>,
        connectors: &'a dyn SectionParser<T, Connectors>,
        name: &'a str,
    ) -> Self {
        Self {
            listeners,
            connectors,
            name,
        }
    }
}

impl<T> ServiceSectionParser<T> for ServiceSection<'_, T> {
    fn parse_node(&self, node: &T) -> miette::Result<ProxyConfig> {
        let listeners = self.listeners.parse_node(node)?;
        let connectors = self.connectors.parse_node(node)?;

        Ok(ProxyConfig {
            name: self.name.to_string(),
            listeners,
            connectors,
        })
    }
}
