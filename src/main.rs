use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use lattice_scan::{scan, ScanOptions, Severity};

/// Scan a domain's public TLS certificates: expiry, chain trust, key strength, post-quantum key exchange,
/// CAA and HSTS, with hostnames discovered from Certificate Transparency logs.
#[derive(Parser)]
#[command(name = "lattice-scan", version)]
struct Args {
    /// Domain to scan, e.g. example.com
    domain: String,
    /// Print the full report as JSON
    #[arg(long)]
    json: bool,
    /// Most hostnames to connect to
    #[arg(long, default_value_t = 20)]
    max_hosts: usize,
    /// Parallel connections
    #[arg(long, default_value_t = 8)]
    concurrency: usize,
    /// Per-connection timeout in seconds
    #[arg(long, default_value_t = 6)]
    timeout: u64,
    /// Skip Certificate Transparency discovery (check the domain and www only)
    #[arg(long)]
    no_ct: bool,
    /// Exit with status 2 when any finding is at or above this severity (info, low, medium, high, critical)
    #[arg(long)]
    fail_on: Option<String>,
}

fn sev(s: &str) -> Option<Severity> {
    Some(match s {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => return None,
    })
}

#[tokio::main]
async fn main() -> ExitCode {
    let a = Args::parse();
    let fail_on = match a.fail_on.as_deref().map(|s| sev(s).ok_or(s)) {
        Some(Err(s)) => {
            eprintln!("--fail-on: unknown severity \"{s}\"");
            return ExitCode::from(64);
        }
        Some(Ok(s)) => Some(s),
        None => None,
    };
    let opts = ScanOptions { max_hosts: a.max_hosts, concurrency: a.concurrency, timeout: Duration::from_secs(a.timeout), ct: !a.no_ct, ..Default::default() };
    let r = match scan(&a.domain, &opts).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(64);
        }
    };
    if a.json {
        println!("{}", serde_json::to_string_pretty(&r).expect("json"));
    } else {
        println!("{}  grade {} ({}/100)\n", r.domain, r.grade, r.score);
        println!("{:<38} {:<9} {:>6} {:>5}  {:<18} {}", "HOST", "TLS", "DAYS", "LIFE", "KEY EXCHANGE", "ISSUER");
        for h in &r.hosts {
            match &h.cert {
                Some(c) => println!(
                    "{:<38} {:<9} {:>6} {:>5}  {:<18} {}{}",
                    h.host,
                    h.tls_version.as_deref().unwrap_or("-"),
                    c.days_remaining,
                    c.lifetime_days,
                    h.key_exchange.as_deref().unwrap_or("-"),
                    c.issuer,
                    h.chain_error.as_ref().map(|e| format!("  [{}]", e.split(':').next().unwrap_or(e))).unwrap_or_default()
                ),
                None => println!("{:<38} {}", h.host, h.status.replace('_', " ")),
            }
        }
        if r.ct.available {
            println!("\nCT logs: {} unexpired certificates, {} hostnames, issuers: {}", r.ct.certificates, r.ct.hostnames, r.ct.issuers.iter().map(|(n, c)| format!("{n} ({c})")).collect::<Vec<_>>().join(", "));
        }
        println!("CAA: {}", if r.policy.caa.is_empty() { "none".into() } else { r.policy.caa.join("; ") });
        println!("HSTS: {}\n", r.policy.hsts.as_deref().unwrap_or("not set"));
        for f in &r.findings {
            println!("[{:?}] {}{}", f.severity, f.title, if f.hosts.is_empty() { String::new() } else { format!(": {}", f.hosts.join(", ")) });
            println!("    {}", f.detail);
        }
    }
    if let Some(min) = fail_on {
        if r.findings.iter().any(|f| f.severity >= min) {
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}
