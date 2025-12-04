
use std::collections::BTreeMap;

use async_trait::async_trait;
use cidr::IpCidr;
use pingora::ErrorType;
use pingora_core::{protocols::l4::socket::SocketAddr, Error, Result};
use pingora_proxy::Session;

use crate::proxy::{RiverContext, filters::{builtin::helpers::extract_val, types::RequestFilterMod}};


pub struct CidrRangeFilter {
    blocks: Vec<IpCidr>,
}

impl CidrRangeFilter {
    /// Create from the settings field
    pub fn from_settings(mut settings: BTreeMap<String, String>) -> Result<Self> {
        let mat = extract_val("addrs", &mut settings)?;

        let addrs = mat.split(',');

        let mut blocks = vec![];
        for addr in addrs {
            let addr = addr.trim();
            match addr.parse::<IpCidr>() {
                Ok(a) => {
                    blocks.push(a);
                }
                Err(_) => {
                    tracing::error!("Failed to parse '{addr}' as a valid CIDR notation range");
                    return Err(Error::new(ErrorType::Custom("Invalid configuration")));
                }
            };
        }

        Ok(Self { blocks })
    }
}

#[async_trait]
impl RequestFilterMod for CidrRangeFilter {
    async fn request_filter(&self, session: &mut Session, _ctx: &mut RiverContext) -> Result<bool> {
        let Some(addr) = session.downstream_session.client_addr() else {
            // Unable to determine source address, assuming it should be blocked
            session.downstream_session.respond_error(401).await?;
            return Ok(true);
        };
        let SocketAddr::Inet(addr) = addr else {
            // CIDR filters don't apply to UDS
            return Ok(false);
        };
        let ip_addr = addr.ip();

        if self.blocks.iter().any(|b| b.contains(&ip_addr)) {
            session.downstream_session.respond_error(401).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_from_settings_valid_ipv4() {
        let mut settings = BTreeMap::new();
        settings.insert("addrs".to_string(), "192.168.0.0/16, 10.0.0.0/8".to_string());

        let filter = CidrRangeFilter::from_settings(settings).expect("Should successfully create filter");

        assert_eq!(filter.blocks.len(), 2);
        assert!(filter.blocks.iter().any(|b| b.to_string() == "192.168.0.0/16"));
        assert!(filter.blocks.iter().any(|b| b.to_string() == "10.0.0.0/8"));
    }

    #[test]
    fn test_from_settings_valid_mixed_ipv4_ipv6() {
        let mut settings = BTreeMap::new();
        settings.insert("addrs".to_string(), "10.0.0.0/8, 2001:db8::/32, ::1/128, 1.1.1.1/32".to_string());

        let filter = CidrRangeFilter::from_settings(settings).expect("Should successfully create filter");
        
        assert_eq!(filter.blocks.len(), 4);
        assert!(filter.blocks.iter().any(|b| b.to_string() == "2001:db8::/32"));
        assert!(filter.blocks.iter().any(|b| b.to_string() == "::1"));
        assert!(filter.blocks.iter().any(|b| b.to_string() == "1.1.1.1"));
    }

    #[test]
    fn test_from_settings_invalid_cidr() {
        let mut settings = BTreeMap::new();
        settings.insert("addrs".to_string(), "192.168.0.0/16, not_a_cidr, 10.0.0.0/8".to_string());

        let result = CidrRangeFilter::from_settings(settings);

        assert!(result.is_err());
        
        let err = result.err().unwrap();
        assert!(format!("{:?}", err).contains("Invalid configuration"));
    }

    #[test]
    fn test_from_settings_missing_addrs_key() {
        let settings = BTreeMap::new(); 
        

        let result = CidrRangeFilter::from_settings(settings);

        assert!(result.is_err());
        
        let err = result.err().unwrap();
        assert!(format!("{:?}", err).contains("Missing configuration"));
    }
    
}