

mod common; 
mod tests {

    use reqwest::Client;
    use crate::common::test_setup::{setup_check_cidr, setup_check_cidr_accept};

    #[tokio::test]
    async fn integration_cidr_block_loopback() {
                
        let handle = setup_check_cidr().await;

        const PROXY_ADDR: &str = "127.0.0.1:8081";

        let client = Client::builder()
            .connect_timeout(std::time::Duration::from_secs(1))
            .build()
            .expect("Failed to create reqwest client");

        let response_blocked = client.get(format!("http://{}/", PROXY_ADDR))
            .send().await
            .expect("Request failed");
                                
        assert_eq!(response_blocked.status().as_u16(), 401, "Connection from 127.0.0.1 should be blocked");
        
        handle.thread().unpark();
    }

    #[tokio::test]
    async fn integration_cidr_accept_loopback() {
                
        let handle = setup_check_cidr_accept().await;

        const PROXY_ADDR: &str = "127.0.0.1:8082";

        let client = Client::builder()
            .connect_timeout(std::time::Duration::from_secs(1))
            .build()
            .expect("Failed to create reqwest client");

        let response_blocked = client.get(format!("http://{}/", PROXY_ADDR))
            .send().await
            .expect("Request failed");
                                
        assert_eq!(response_blocked.status().as_u16(), 200, "Connection from 127.0.0.1 should not be blocked");
        handle.thread().unpark();
    }
}
