//! Report types and grading. Everything here is serializable so the same report feeds the CLI, the JSON output
//! and the LatticePKI web report.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn penalty(self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 2,
            Severity::Medium => 6,
            Severity::High => 15,
            Severity::Critical => 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Stable identifier, e.g. "expired", "no_pq_kex".
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    /// Hostnames the finding applies to; empty for domain-wide findings.
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInfo {
    pub subject_cn: Option<String>,
    pub sans: Vec<String>,
    pub issuer: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub lifetime_days: i64,
    pub days_remaining: i64,
    /// e.g. "RSA 2048", "EC P-256", "Ed25519".
    pub key: String,
    pub signature_algorithm: String,
    pub serial: String,
    pub sha256_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResult {
    pub host: String,
    pub addresses: Vec<String>,
    /// "ok", "no_dns", "private_address", "connect_failed", "handshake_failed".
    pub status: String,
    pub error: Option<String>,
    pub tls_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub key_exchange: Option<String>,
    pub post_quantum_kex: bool,
    /// None when the chain verified; otherwise why it did not.
    pub chain_error: Option<String>,
    pub chain: Vec<String>,
    pub cert: Option<CertInfo>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CtSummary {
    pub available: bool,
    pub error: Option<String>,
    /// Unexpired certificates logged for the domain and its subdomains.
    pub certificates: usize,
    pub hostnames: usize,
    pub wildcard_certificates: usize,
    /// Issuer organisation → certificate count.
    pub issuers: Vec<(String, usize)>,
    /// Median lifetime of logged certificates, in days.
    pub median_lifetime_days: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DomainPolicy {
    pub caa: Vec<String>,
    pub hsts: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifetimeStage {
    pub effective: String,
    pub max_days: i64,
    pub renewals_per_year: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub domain: String,
    pub scanned_at: DateTime<Utc>,
    pub scanner_version: String,
    pub grade: String,
    pub score: u32,
    pub hosts: Vec<HostResult>,
    pub ct: CtSummary,
    pub policy: DomainPolicy,
    pub findings: Vec<Finding>,
    /// CA/Browser Forum Ballot SC-081v3 schedule for maximum public TLS certificate lifetime.
    pub lifetime_schedule: Vec<LifetimeStage>,
}

pub fn lifetime_schedule() -> Vec<LifetimeStage> {
    vec![
        LifetimeStage { effective: "2026-03-15".into(), max_days: 200, renewals_per_year: 2.0 },
        LifetimeStage { effective: "2027-03-15".into(), max_days: 100, renewals_per_year: 4.0 },
        LifetimeStage { effective: "2029-03-15".into(), max_days: 47, renewals_per_year: 8.0 },
    ]
}

/// Score from 100 down. Each finding id counts once, at its severity; a critical finding caps the grade at D.
pub fn grade(findings: &[Finding]) -> (u32, String) {
    let mut seen = std::collections::HashSet::new();
    let mut penalty = 0u32;
    let mut critical = false;
    for f in findings {
        if seen.insert(f.id.as_str()) {
            penalty += f.severity.penalty();
        }
        critical |= f.severity == Severity::Critical;
    }
    let score = 100u32.saturating_sub(penalty);
    let mut g = match score {
        90..=100 => "A",
        80..=89 => "B",
        70..=79 => "C",
        55..=69 => "D",
        _ => "F",
    };
    if critical && matches!(g, "A" | "B" | "C") {
        g = "D";
    }
    (score, g.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(id: &str, s: Severity) -> Finding {
        Finding { id: id.into(), severity: s, title: String::new(), detail: String::new(), hosts: vec![] }
    }

    #[test]
    fn clean_report_is_a() {
        assert_eq!(grade(&[]), (100, "A".into()));
    }

    #[test]
    fn critical_caps_at_d() {
        let (score, g) = grade(&[f("expired", Severity::Critical)]);
        assert_eq!(score, 70);
        assert_eq!(g, "D");
    }

    #[test]
    fn repeated_ids_count_once() {
        let (score, _) = grade(&[f("no_caa", Severity::Medium), f("no_caa", Severity::Medium)]);
        assert_eq!(score, 94);
    }
}
