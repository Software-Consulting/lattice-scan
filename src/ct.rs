//! Certificate Transparency discovery through SSLMate's Cert Spotter API, with crt.sh's public JSON interface as
//! the fallback.
//!
//! CT logs list every publicly trusted certificate, so they show hostnames a team may have forgotten about. We only
//! ask for unexpired certificates and only read what crt.sh already publishes.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

use chrono::{NaiveDateTime, TimeZone, Utc};
use serde::Deserialize;

use crate::net::in_domain;
use crate::report::CtSummary;

#[derive(Debug, Deserialize)]
struct CrtShRow {
    id: u64,
    issuer_name: Option<String>,
    name_value: Option<String>,
    not_before: Option<String>,
    not_after: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CtResult {
    pub summary: CtSummary,
    /// Hostnames from logged certificates, most recently issued first, wildcards stripped of "*.".
    pub hostnames: Vec<String>,
}

fn parse_time(s: &str) -> Option<chrono::DateTime<Utc>> {
    NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S").ok().map(|n| Utc.from_utc_datetime(&n))
}

/// Organisation from an X.500 name such as `C=US, O="DigiCert, Inc.", CN=...`; falls back to the CN.
pub fn issuer_org(name: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in name.chars() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                parts.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    parts.push(cur.trim().to_string());
    let get = |k: &str| parts.iter().find_map(|p| p.strip_prefix(k).map(|v| v.trim().to_string()));
    get("O=").or_else(|| get("CN=")).unwrap_or_else(|| name.to_string())
}

async fn query(client: &reqwest::Client, q: &str) -> Result<Vec<CrtShRow>, String> {
    let url = format!("https://crt.sh/?q={}&output=json&exclude=expired&deduplicate=Y", q.replace('%', "%25"));
    let resp = client.get(&url).send().await.map_err(|e| format!("crt.sh unreachable: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("crt.sh returned {}", resp.status()));
    }
    let text = resp.text().await.map_err(|e| format!("crt.sh read failed: {e}"))?;
    if text.trim().is_empty() {
        return Ok(vec![]);
    }
    serde_json::from_str(&text).map_err(|e| format!("crt.sh returned unexpected data: {e}"))
}

#[derive(Debug, Deserialize)]
struct SpotterIssuer {
    friendly_name: Option<String>,
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SpotterRow {
    id: String,
    dns_names: Option<Vec<String>>,
    issuer: Option<SpotterIssuer>,
    not_before: Option<String>,
    not_after: Option<String>,
}

/// SSLMate Cert Spotter: unexpired issuances for the domain and its subdomains. Pages through up to 5 pages.
async fn certspotter(client: &reqwest::Client, domain: &str) -> Result<Vec<CrtShRow>, String> {
    let mut out = Vec::new();
    let mut after: Option<String> = None;
    for _ in 0..5 {
        let mut url = format!("https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names&expand=issuer");
        if let Some(a) = &after {
            url.push_str(&format!("&after={a}"));
        }
        let resp = client.get(&url).send().await.map_err(|e| format!("Cert Spotter unreachable: {e}"))?;
        if !resp.status().is_success() {
            return if out.is_empty() { Err(format!("Cert Spotter returned {}", resp.status())) } else { Ok(out) };
        }
        let rows: Vec<SpotterRow> = resp.json().await.map_err(|e| format!("Cert Spotter returned unexpected data: {e}"))?;
        let n = rows.len();
        after = rows.last().map(|r| r.id.clone());
        for r in rows {
            let issuer = r.issuer.map(|i| i.name.or(i.friendly_name).unwrap_or_default());
            out.push(CrtShRow {
                id: r.id.parse().unwrap_or(0),
                issuer_name: issuer,
                name_value: r.dns_names.map(|v| v.join("\n")),
                not_before: r.not_before.map(|s| s.trim_end_matches('Z').to_string()),
                not_after: r.not_after.map(|s| s.trim_end_matches('Z').to_string()),
            });
        }
        if n < 100 {
            break;
        }
    }
    Ok(out)
}

pub async fn discover(domain: &str, timeout: Duration) -> CtResult {
    let client = match reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(concat!("lattice-scan/", env!("CARGO_PKG_VERSION"), " (+https://latticepki.com)"))
        .build()
    {
        Ok(c) => c,
        Err(e) => return failed(format!("http client: {e}")),
    };
    let mut errors = Vec::new();
    let mut rows = match certspotter(&client, domain).await {
        Ok(v) => v,
        Err(e) => {
            errors.push(e);
            Vec::new()
        }
    };
    if !errors.is_empty() {
        // Fall back to crt.sh.
        let wildcard = format!("%.{domain}");
        let (a, b) = tokio::join!(query(&client, domain), query(&client, &wildcard));
        for r in [a, b] {
            match r {
                Ok(mut v) => rows.append(&mut v),
                Err(e) => errors.push(e),
            }
        }
        if !rows.is_empty() {
            errors.clear();
        }
    }
    if rows.is_empty() && !errors.is_empty() {
        return failed(errors.join("; "));
    }

    let mut by_id: BTreeMap<u64, CrtShRow> = BTreeMap::new();
    for r in rows {
        by_id.entry(r.id).or_insert(r);
    }
    let mut issuers: HashMap<String, usize> = HashMap::new();
    let mut lifetimes = Vec::new();
    let mut wildcards = 0usize;
    // Newest first: crt.sh ids grow over time.
    let mut ordered: Vec<String> = Vec::new();
    let mut seen = BTreeSet::new();
    for r in by_id.values().rev() {
        let org = issuer_org(r.issuer_name.as_deref().unwrap_or("Unknown"));
        *issuers.entry(org).or_default() += 1;
        if let (Some(nb), Some(na)) = (r.not_before.as_deref().and_then(parse_time), r.not_after.as_deref().and_then(parse_time)) {
            lifetimes.push((na - nb).num_days());
        }
        let mut has_wild = false;
        for n in r.name_value.as_deref().unwrap_or("").lines() {
            let n = n.trim().to_ascii_lowercase();
            let (n, wild) = match n.strip_prefix("*.") {
                Some(rest) => (rest.to_string(), true),
                None => (n, false),
            };
            has_wild |= wild;
            if in_domain(&n, domain) && !n.contains('@') && seen.insert(n.clone()) {
                ordered.push(n);
            }
        }
        if has_wild {
            wildcards += 1;
        }
    }
    lifetimes.sort_unstable();
    let median = (!lifetimes.is_empty()).then(|| lifetimes[lifetimes.len() / 2]);
    let mut issuers: Vec<(String, usize)> = issuers.into_iter().collect();
    issuers.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    CtResult {
        summary: CtSummary {
            available: true,
            error: (!errors.is_empty()).then(|| errors.join("; ")),
            certificates: by_id.len(),
            hostnames: ordered.len(),
            wildcard_certificates: wildcards,
            issuers,
            median_lifetime_days: median,
        },
        hostnames: ordered,
    }
}

fn failed(e: String) -> CtResult {
    CtResult { summary: CtSummary { available: false, error: Some(e), ..Default::default() }, hostnames: vec![] }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_names() {
        assert_eq!(issuer_org("C=US, O=Let's Encrypt, CN=R11"), "Let's Encrypt");
        assert_eq!(issuer_org("C=US, O=\"DigiCert, Inc.\", CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1"), "DigiCert, Inc.");
        assert_eq!(issuer_org("CN=Some CA"), "Some CA");
    }
}
