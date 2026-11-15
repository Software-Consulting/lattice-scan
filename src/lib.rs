//! lattice-scan: scan a domain's public TLS certificates.
//!
//! ```no_run
//! # async fn run() {
//! let report = lattice_scan::scan("example.com", &lattice_scan::ScanOptions::default()).await.unwrap();
//! println!("{} {}", report.domain, report.grade);
//! # }
//! ```
//!
//! The scan only does what any browser does: it reads public Certificate Transparency logs, looks up DNS and opens
//! TLS connections to port 443 of the domain's own hostnames. It never connects to private or reserved addresses.

pub mod ct;
pub mod dns;
pub mod net;
pub mod report;
pub mod tls;

use std::collections::BTreeSet;
use std::time::Duration;

use chrono::Utc;
use futures::stream::{self, StreamExt};

pub use report::*;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Most hostnames to connect to (the domain and www first, then names from CT logs, newest first).
    pub max_hosts: usize,
    pub concurrency: usize,
    /// Per-connection timeout for TCP connect and TLS handshake.
    pub timeout: Duration,
    /// Query Certificate Transparency logs (crt.sh).
    pub ct: bool,
    pub ct_timeout: Duration,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self { max_hosts: 20, concurrency: 8, timeout: Duration::from_secs(6), ct: true, ct_timeout: Duration::from_secs(25) }
    }
}

const SENSITIVE: &[&str] = &["dev", "staging", "stage", "test", "uat", "internal", "intranet", "vpn", "admin", "jenkins", "gitlab", "grafana", "kibana", "vault", "jira", "confluence", "sso", "remote"];

pub async fn scan(input: &str, opts: &ScanOptions) -> Result<Report, String> {
    let domain = net::normalize_domain(input)?;
    let ct_fut = async {
        if opts.ct {
            Some(ct::discover(&domain, opts.ct_timeout).await)
        } else {
            None
        }
    };
    let (ct, caa, hsts) = tokio::join!(ct_fut, dns::caa(&domain), hsts(&domain, opts.timeout));

    let mut hosts: Vec<(String, bool)> = vec![(domain.clone(), false)];
    if !domain.starts_with("www.") {
        hosts.push((format!("www.{domain}"), false));
    }
    let mut seen: BTreeSet<String> = hosts.iter().map(|h| h.0.clone()).collect();
    if let Some(ct) = &ct {
        for h in &ct.hostnames {
            if hosts.len() >= opts.max_hosts {
                break;
            }
            if seen.insert(h.clone()) {
                hosts.push((h.clone(), true));
            }
        }
    }

    let limit = opts.timeout;
    let mut results: Vec<(HostResult, bool)> = stream::iter(hosts)
        .map(|(h, from_ct)| async move { (probe(&h, limit).await, from_ct) })
        .buffer_unordered(opts.concurrency.max(1))
        .collect()
        .await;
    results.sort_by(|a, b| (a.0.host != domain).cmp(&(b.0.host != domain)).then(a.0.host.cmp(&b.0.host)));

    let ct_summary = ct.map(|c| c.summary).unwrap_or_default();
    let ct_names: Vec<String> = results.iter().filter(|r| r.1).map(|r| r.0.host.clone()).collect();
    let mut findings = findings(&domain, &results, &ct_summary, &caa, hsts.as_deref(), &ct_names);
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(&b.id)));
    let (score, grade) = report::grade(&findings);

    Ok(Report {
        domain,
        scanned_at: Utc::now(),
        scanner_version: env!("CARGO_PKG_VERSION").to_string(),
        grade,
        score,
        hosts: results.into_iter().map(|r| r.0).collect(),
        ct: ct_summary,
        policy: DomainPolicy { caa, hsts },
        findings,
        lifetime_schedule: report::lifetime_schedule(),
    })
}

async fn probe(host: &str, limit: Duration) -> HostResult {
    let mut r = HostResult {
        host: host.to_string(),
        addresses: vec![],
        status: "ok".into(),
        error: None,
        tls_version: None,
        cipher_suite: None,
        key_exchange: None,
        post_quantum_kex: false,
        chain_error: None,
        chain: vec![],
        cert: None,
    };
    let ips = dns::addresses(host).await;
    r.addresses = ips.iter().map(|i| i.to_string()).collect();
    let Some(ip) = ips.iter().find(|i| net::is_public(i)).copied() else {
        r.status = if ips.is_empty() { "no_dns" } else { "private_address" }.into();
        return r;
    };
    match tls::handshake(host, ip, limit).await {
        Err((status, msg)) => {
            r.status = status;
            r.error = Some(msg);
        }
        Ok(o) => {
            r.tls_version = Some(o.tls_version);
            r.cipher_suite = Some(o.cipher_suite);
            r.post_quantum_kex = o.key_exchange.as_deref().is_some_and(|k| k.to_ascii_uppercase().contains("MLKEM"));
            r.key_exchange = o.key_exchange;
            r.chain = o.chain.iter().map(tls::subject_cn).collect();
            r.cert = o.chain.first().and_then(tls::parse_leaf);
            r.chain_error = tls::verify_chain(host, &o.chain).map(|(id, msg)| format!("{id}: {msg}"));
        }
    }
    r
}

async fn hsts(domain: &str, limit: Duration) -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(limit * 2)
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent(concat!("lattice-scan/", env!("CARGO_PKG_VERSION"), " (+https://latticepki.com)"))
        .build()
        .ok()?;
    let resp = client.get(format!("https://{domain}/")).send().await.ok()?;
    resp.headers().get("strict-transport-security").and_then(|v| v.to_str().ok()).map(String::from)
}

fn finding(id: &str, severity: Severity, title: &str, detail: String, hosts: Vec<String>) -> Finding {
    Finding { id: id.into(), severity, title: title.into(), detail, hosts }
}

fn findings(domain: &str, results: &[(HostResult, bool)], ct: &CtSummary, caa: &[String], hsts: Option<&str>, _ct_names: &[String]) -> Vec<Finding> {
    let mut out = Vec::new();
    let hosts = |pred: &dyn Fn(&HostResult) -> bool| -> Vec<String> { results.iter().filter(|r| pred(&r.0)).map(|r| r.0.host.clone()).collect() };
    let chain_is = |r: &HostResult, id: &str| r.chain_error.as_deref().is_some_and(|e| e.starts_with(id));

    let h = hosts(&|r| r.cert.as_ref().is_some_and(|c| c.days_remaining < 0) || chain_is(r, "expired"));
    if !h.is_empty() {
        out.push(finding("expired", Severity::Critical, "Expired certificate in use", "Browsers block these hostnames with a full-page warning. Renew and redeploy the certificate now.".into(), h));
    }
    let h = hosts(&|r| chain_is(r, "name_mismatch"));
    if !h.is_empty() {
        out.push(finding("name_mismatch", Severity::Critical, "Certificate does not cover the hostname", "The certificate served does not list this hostname, so browsers show a warning. Reissue it with the right names or fix which certificate the server presents.".into(), h));
    }
    let h = hosts(&|r| chain_is(r, "untrusted_issuer") || chain_is(r, "revoked") || chain_is(r, "invalid") || chain_is(r, "not_yet_valid") || chain_is(r, "no_certificate"));
    if !h.is_empty() {
        out.push(finding("untrusted_chain", Severity::Critical, "Certificate chain is not trusted", "Browsers cannot build a path from this certificate to a trusted root. Often a missing intermediate certificate or a private CA on a public hostname.".into(), h));
    }
    let h = hosts(&|r| r.cert.as_ref().is_some_and(|c| (0..14).contains(&c.days_remaining)));
    if !h.is_empty() {
        out.push(finding("expires_14", Severity::High, "Certificate expires within 14 days", "Renew before it lapses. If renewal is automated, check that the automation actually ran.".into(), h));
    }
    let h = hosts(&|r| r.cert.as_ref().is_some_and(|c| (14..30).contains(&c.days_remaining)));
    if !h.is_empty() {
        out.push(finding("expires_30", Severity::Medium, "Certificate expires within 30 days", "Plan the renewal now, or confirm the automated renewal is scheduled.".into(), h));
    }
    let h = hosts(&|r| r.cert.as_ref().is_some_and(|c| c.key.starts_with("RSA ") && c.key[4..].parse::<u32>().is_ok_and(|b| b < 2048)));
    if !h.is_empty() {
        out.push(finding("weak_key", Severity::Critical, "RSA key shorter than 2048 bits", "Keys this short are no longer accepted by publicly trusted CAs. Generate a new key (RSA 2048+ or ECDSA P-256) and reissue.".into(), h));
    }
    let h = hosts(&|r| r.cert.as_ref().is_some_and(|c| c.signature_algorithm.contains("SHA-1")));
    if !h.is_empty() {
        out.push(finding("sha1_signature", Severity::Critical, "SHA-1 signature", "SHA-1 signed certificates are rejected by modern browsers. Reissue with SHA-256 or better.".into(), h));
    }
    let h = hosts(&|r| r.status == "handshake_failed");
    if !h.is_empty() {
        out.push(finding("handshake_failed", Severity::High, "TLS handshake fails", "These hostnames answer on port 443 but a modern client cannot complete a TLS handshake. Usually TLS 1.0/1.1 only, or a misconfigured server.".into(), h));
    }
    let h = hosts(&|r| r.cert.as_ref().is_some_and(|c| c.lifetime_days > 100));
    if !h.is_empty() {
        out.push(finding(
            "long_lifetime",
            Severity::Medium,
            "Long-lived certificates point to manual renewal",
            "These certificates were issued for more than 100 days. From March 15, 2027 the maximum is 100 days, and from March 15, 2029 it is 47, so each certificate will need renewing about 8 times a year. Anything renewed by hand today needs ACME or another automated renewal before then.".into(),
            h,
        ));
    }
    let h = hosts(&|r| r.tls_version.as_deref() == Some("TLS 1.2"));
    if !h.is_empty() {
        out.push(finding("no_tls13", Severity::Low, "TLS 1.3 not offered", "These servers negotiated TLS 1.2 although TLS 1.3 was offered. TLS 1.3 is faster and is required for post-quantum key exchange.".into(), h));
    }
    let h = hosts(&|r| r.status == "ok" && !r.post_quantum_kex);
    if !h.is_empty() {
        out.push(finding(
            "no_pq_kex",
            Severity::Low,
            "No post-quantum key exchange",
            "These servers did not accept the hybrid X25519MLKEM768 key exchange that current browsers offer by default. Traffic recorded today could be decrypted later by a quantum computer (\"harvest now, decrypt later\"). Most current TLS libraries and CDNs support it; it is usually a library upgrade or a configuration change.".into(),
            h,
        ));
    }
    if results.iter().all(|r| r.0.cert.is_none()) {
        out.push(finding("no_https", Severity::High, "No HTTPS found", format!("Neither {domain} nor any hostname we checked served a certificate on port 443."), vec![]));
    }
    let h: Vec<String> = results.iter().filter(|r| r.1 && r.0.status == "no_dns").map(|r| r.0.host.clone()).collect();
    if !h.is_empty() {
        out.push(finding("stale_names", Severity::Info, "Names in CT logs that no longer resolve", "Unexpired certificates still cover these names but they have no DNS records. Retire old certificates and keep the inventory current; the private keys still exist somewhere.".into(), h));
    }
    let h: Vec<String> = results.iter().filter(|r| r.0.status == "private_address").map(|r| r.0.host.clone()).collect();
    if !h.is_empty() {
        out.push(finding("internal_names", Severity::Low, "Internal hostnames published in public logs", "These names resolve to private addresses but appear in public Certificate Transparency logs, which maps part of your internal network for anyone. An internal CA avoids this.".into(), h));
    }
    let h: Vec<String> = results
        .iter()
        .filter(|r| r.1)
        .map(|r| r.0.host.clone())
        .filter(|n| n.split(['.', '-']).any(|l| SENSITIVE.contains(&l)))
        .collect();
    if !h.is_empty() {
        out.push(finding("sensitive_names", Severity::Low, "Sensitive-looking hostnames in public logs", "Names like these tell attackers where admin, development or remote-access systems live. Consider wildcard or internal certificates for them.".into(), h));
    }
    if ct.wildcard_certificates > 0 {
        out.push(finding("wildcards", Severity::Info, "Wildcard certificates in use", format!("{} unexpired wildcard certificate(s). One private key then protects many hostnames, so a leak on any server exposes all of them.", ct.wildcard_certificates), vec![]));
    }
    if ct.issuers.len() > 3 {
        let names: Vec<String> = ct.issuers.iter().map(|(n, c)| format!("{n} ({c})")).collect();
        out.push(finding("issuer_sprawl", Severity::Low, "Certificates from many CAs", format!("Unexpired certificates come from {} issuers: {}. Each CA is a separate renewal process to keep working as lifetimes shrink.", ct.issuers.len(), names.join(", ")), vec![]));
    }
    if !ct.available {
        out.push(finding("ct_unavailable", Severity::Info, "Certificate Transparency lookup unavailable", format!("We could not reach the CT log search ({}), so only {domain} and www were checked.", ct.error.clone().unwrap_or_default()), vec![]));
    }
    if caa.is_empty() {
        out.push(finding("no_caa", Severity::Medium, "No CAA record", "A CAA DNS record lists which CAs may issue certificates for your domain. Without one, any public CA can. Add one naming the CAs you actually use.".into(), vec![]));
    }
    match hsts {
        None => out.push(finding("no_hsts", Severity::Medium, "HSTS not set", format!("https://{domain}/ does not send Strict-Transport-Security, so browsers may still try plain HTTP first.")
            , vec![])),
        Some(v) => {
            let max_age = v.split(';').find_map(|p| p.trim().strip_prefix("max-age=").and_then(|n| n.trim_matches('"').parse::<u64>().ok())).unwrap_or(0);
            if max_age < 15_552_000 {
                out.push(finding("short_hsts", Severity::Low, "Short HSTS max-age", format!("max-age is {max_age} seconds; six months (15552000) or more is recommended."), vec![]));
            }
        }
    }
    out
}
