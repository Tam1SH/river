use leaky_bucket::RateLimiter;
use pingora_proxy::Session;
use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use crate::legacy::something::{RegexShim, Ticket};

#[derive(Debug, PartialEq, Clone)]
pub struct SingleInstanceConfig {
    /// The max and initial number of tokens in the leaky bucket - this is the number of
    /// requests that can go through without any waiting if the bucket is full
    pub max_tokens_per_bucket: NonZeroUsize,
    /// The interval between "refills" of the bucket, e.g. the bucket refills `refill_qty`
    /// every `refill_interval_millis`
    pub refill_interval_millis: NonZeroUsize,
    /// The number of tokens added to the bucket every `refill_interval_millis`
    pub refill_qty: NonZeroUsize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SingleRequestKeyKind {
    UriGroup { pattern: RegexShim },
}

#[derive(Debug)]
pub struct SingleInstance {
    pub limiter: Arc<RateLimiter>,
    pub kind: SingleRequestKeyKind,
}

impl SingleInstance {
    /// Create a new rate limiter with the given configuration.
    ///
    /// See [`SingleInstanceConfig`] for configuration options.
    pub fn new(config: SingleInstanceConfig, kind: SingleRequestKeyKind) -> Self {
        let SingleInstanceConfig {
            max_tokens_per_bucket,
            refill_interval_millis,
            refill_qty,
        } = config;

        let limiter = RateLimiter::builder()
            .initial(max_tokens_per_bucket.get())
            .max(max_tokens_per_bucket.get())
            .interval(Duration::from_millis(refill_interval_millis.get() as u64))
            .refill(refill_qty.get())
            .fair(true)
            .build();

        let limiter = Arc::new(limiter);

        Self { limiter, kind }
    }

    pub fn get_ticket(&self, uri_path: &Session) -> Option<Ticket> {
        match &self.kind {
            SingleRequestKeyKind::UriGroup { pattern } => {
                let uri_path = uri_path.downstream_session.req_header().uri.path();
                if pattern.is_match(uri_path) {
                    Some(Ticket {
                        limiter: self.limiter.clone(),
                    })
                } else {
                    None
                }
            }
        }
    }
}

#[cfg(test)]
mod test {

    use pingora_proxy::Session;
    use std::io::Cursor;
    use std::num::NonZeroUsize;

    use crate::legacy::{
        single::{SingleInstance, SingleInstanceConfig, SingleRequestKeyKind},
        something::RegexShim,
    };

    #[tokio::test]
    async fn single_instance_get_ticket() {
        let instance = SingleInstance::new(
            SingleInstanceConfig {
                max_tokens_per_bucket: NonZeroUsize::new(1).unwrap(),
                refill_interval_millis: NonZeroUsize::new(1).unwrap(),
                refill_qty: NonZeroUsize::new(1).unwrap(),
            },
            SingleRequestKeyKind::UriGroup {
                pattern: RegexShim::new("static/.*").unwrap(),
            },
        );
        {
            // Create an in-memory buffer simulating raw HTTP request bytes
            let buf = Cursor::new(b"GET /static/42.ext HTTP/1.1\r\n\r\n".to_vec());
            let mut session = Session::new_h1(Box::new(buf));
            session.read_request().await.unwrap();

            let ticket = instance.get_ticket(&session);
            assert!(ticket.is_some());
        }

        {
            let buf = Cursor::new(b"GET /something-else HTTP/1.1\r\n\r\n".to_vec());
            let mut session = Session::new_h1(Box::new(buf));
            session.read_request().await.unwrap();

            let ticket = instance.get_ticket(&session);
            assert!(ticket.is_none());
        }
    }
}
