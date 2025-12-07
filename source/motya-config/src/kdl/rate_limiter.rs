use std::{collections::BTreeMap, num::NonZeroUsize};

use kdl::{KdlDocument, KdlNode, KdlValue};

use crate::{
    common_types::{
        bad::Bad,
        rate_limiter::{AllRateConfig, MultiRaterConfig, RateLimitingConfig},
        section_parser::SectionParser,
    },
    kdl::utils,
    legacy::{
        multi::MultiRequestKeyKind,
        single::{SingleInstanceConfig, SingleRequestKeyKind},
        something::RegexShim,
    },
};
// proxy::rate_limiting::{
//     RegexShim, multi::MultiRequestKeyKind, single::{SingleInstanceConfig, SingleRequestKeyKind}
// },

pub struct RateLimitSection<'a> {
    doc: &'a KdlDocument,
    threads_per_service: usize,
}

impl SectionParser<KdlDocument, RateLimitingConfig> for RateLimitSection<'_> {
    fn parse_node(&self, node: &KdlDocument) -> miette::Result<RateLimitingConfig> {
        let mut rl = RateLimitingConfig::default();
        if let Some(rl_node) = utils::optional_child_doc(self.doc, node, "rate-limiting") {
            let nodes = utils::data_nodes(self.doc, rl_node)?;
            for (node, name, args) in nodes.iter() {
                if *name == "rule" {
                    let vals = utils::str_value_args(self.doc, args)?;
                    let valslice = vals
                        .iter()
                        .map(|(k, v)| (*k, v.value()))
                        .collect::<BTreeMap<&str, &KdlValue>>();
                    rl.rules.push(self.make_rate_limiter(
                        self.threads_per_service,
                        node,
                        valslice,
                    )?);
                } else {
                    return Err(Bad::docspan(
                        format!("Unknown name: '{name}'"),
                        self.doc,
                        &node.span(),
                    )
                    .into());
                }
            }
        }

        Ok(rl)
    }
}

impl<'a> RateLimitSection<'a> {
    pub fn new(doc: &'a KdlDocument, threads_per_service: usize) -> Self {
        Self {
            doc,
            threads_per_service,
        }
    }

    fn make_rate_limiter(
        &self,
        threads_per_service: usize,
        node: &KdlNode,
        args: BTreeMap<&str, &KdlValue>,
    ) -> miette::Result<AllRateConfig> {
        let take_num = |key: &str| -> miette::Result<usize> {
            let Some(val) = args.get(key) else {
                return Err(
                    Bad::docspan(format!("Missing key: '{key}'"), self.doc, &node.span()).into(),
                );
            };
            let Some(val) = val.as_integer().and_then(|v| usize::try_from(v).ok()) else {
                return Err(Bad::docspan(
                    format!(
                        "'{key} should have a positive integer value, got '{:?}' instead",
                        val
                    ),
                    self.doc,
                    &node.span(),
                )
                .into());
            };
            Ok(val)
        };
        let take_str = |key: &str| -> miette::Result<&str> {
            let Some(val) = args.get(key) else {
                return Err(
                    Bad::docspan(format!("Missing key: '{key}'"), self.doc, &node.span()).into(),
                );
            };
            let Some(val) = val.as_string() else {
                return Err(Bad::docspan(
                    format!("'{key} should have a string value, got '{:?}' instead", val),
                    self.doc,
                    &node.span(),
                )
                .into());
            };
            Ok(val)
        };

        // mandatory/common fields
        let kind = take_str("kind")?;
        let tokens_per_bucket =
            NonZeroUsize::new(take_num("tokens-per-bucket")?).ok_or_else(|| {
                Bad::docspan(
                    "'tokens-per-bucket' must be a positive",
                    self.doc,
                    &node.span(),
                )
            })?;

        let refill_qty = NonZeroUsize::new(take_num("refill-qty")?).ok_or_else(|| {
            Bad::docspan("'refill-qty' must be a positive", self.doc, &node.span())
        })?;

        let refill_rate_ms = NonZeroUsize::new(take_num("refill-rate-ms")?).ok_or_else(|| {
            Bad::docspan(
                "'refill-rate-ms' must be a positive",
                self.doc,
                &node.span(),
            )
        })?;

        let multi_cfg = || -> miette::Result<MultiRaterConfig> {
            let max_buckets = take_num("max-buckets")?;
            Ok(MultiRaterConfig {
                threads: threads_per_service,
                max_buckets,
                max_tokens_per_bucket: tokens_per_bucket,
                refill_interval_millis: refill_rate_ms,
                refill_qty,
            })
        };

        let single_cfg = || SingleInstanceConfig {
            max_tokens_per_bucket: tokens_per_bucket,
            refill_interval_millis: refill_rate_ms,
            refill_qty,
        };

        let regex_pattern = || -> miette::Result<RegexShim> {
            let pattern = take_str("pattern")?;
            let Ok(pattern) = RegexShim::new(pattern) else {
                return Err(Bad::docspan(
                    format!("'{pattern} should be a valid regular expression"),
                    self.doc,
                    &node.span(),
                )
                .into());
            };
            Ok(pattern)
        };

        match kind {
            "source-ip" => Ok(AllRateConfig::Multi {
                kind: MultiRequestKeyKind::SourceIp,
                config: multi_cfg()?,
            }),
            "specific-uri" => Ok(AllRateConfig::Multi {
                kind: MultiRequestKeyKind::Uri {
                    pattern: regex_pattern()?,
                },
                config: multi_cfg()?,
            }),
            "any-matching-uri" => Ok(AllRateConfig::Single {
                kind: SingleRequestKeyKind::UriGroup {
                    pattern: regex_pattern()?,
                },
                config: single_cfg(),
            }),
            other => Err(Bad::docspan(
                format!("'{other} is not a known kind of rate limiting"),
                self.doc,
                &node.span(),
            )
            .into()),
        }
    }
}
