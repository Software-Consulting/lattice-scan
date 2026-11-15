//! DNS lookups: addresses for each host and the domain's CAA policy.

use std::net::IpAddr;
use std::sync::OnceLock;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioAsyncResolver;

fn resolver() -> &'static TokioAsyncResolver {
    static R: OnceLock<TokioAsyncResolver> = OnceLock::new();
    R.get_or_init(|| {
        let mut opts = ResolverOpts::default();
        opts.timeout = std::time::Duration::from_secs(4);
        opts.attempts = 2;
        TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), opts)
    })
}

pub async fn addresses(host: &str) -> Vec<IpAddr> {
    match resolver().lookup_ip(format!("{host}.")).await {
        Ok(l) => {
            let mut v: Vec<IpAddr> = l.iter().collect();
            v.sort();
            v.dedup();
            v
        }
        Err(_) => vec![],
    }
}

/// CAA records for the domain, climbing to the parent the way CAs do when the name itself has none.
pub async fn caa(domain: &str) -> Vec<String> {
    let mut name = domain.to_string();
    loop {
        if let Ok(l) = resolver().lookup(format!("{name}."), RecordType::CAA).await {
            let v: Vec<String> = l.record_iter().filter_map(|r| r.data().map(|d| d.to_string())).collect();
            if !v.is_empty() {
                return v;
            }
        }
        match name.split_once('.') {
            Some((_, parent)) if parent.contains('.') => name = parent.to_string(),
            _ => return vec![],
        }
    }
}
