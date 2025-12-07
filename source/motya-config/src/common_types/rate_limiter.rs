use std::num::NonZeroUsize;

use crate::legacy::{
    multi::MultiRequestKeyKind,
    single::{SingleInstanceConfig, SingleRequestKeyKind},
};

#[derive(Debug, Clone, PartialEq)]
pub struct MultiRaterInstanceConfig {
    pub rater_cfg: MultiRaterConfig,
    pub kind: MultiRequestKeyKind,
}

/// Configuration for the [`Rater`]
#[derive(Debug, PartialEq, Clone)]
pub struct MultiRaterConfig {
    /// The number of expected concurrent threads - should match the number of
    /// tokio threadpool workers
    pub threads: usize,
    /// The peak number of leaky buckets we aim to have live at once
    ///
    /// NOTE: This is not a hard limit of the amount of memory used. See [`ARCacheBuilder`]
    /// for docs on calculating actual memory usage based on these parameters
    pub max_buckets: usize,
    /// The max and initial number of tokens in the leaky bucket - this is the number of
    /// requests that can go through without any waiting if the bucket is full
    pub max_tokens_per_bucket: NonZeroUsize,
    /// The interval between "refills" of the bucket, e.g. the bucket refills `refill_qty`
    /// every `refill_interval_millis`
    pub refill_interval_millis: NonZeroUsize,
    /// The number of tokens added to the bucket every `refill_interval_millis`
    pub refill_qty: NonZeroUsize,
}

#[derive(Debug, PartialEq, Clone)]
pub enum AllRateConfig {
    Single {
        kind: SingleRequestKeyKind,
        config: SingleInstanceConfig,
    },
    Multi {
        kind: MultiRequestKeyKind,
        config: MultiRaterConfig,
    },
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct RateLimitingConfig {
    pub(crate) rules: Vec<AllRateConfig>,
}
