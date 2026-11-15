//! Domain input handling and address safety checks.

use std::net::IpAddr;

/// Normalise user input ("https://WWW.Example.com:443/path") to a bare lowercase domain ("www.example.com").
/// Rejects IP addresses, single labels and anything that is not a plain ASCII hostname.
pub fn normalize_domain(input: &str) -> Result<String, String> {
    let mut s = input.trim().to_ascii_lowercase();
    for p in ["https://", "http://"] {
        if let Some(rest) = s.strip_prefix(p) {
            s = rest.to_string();
        }
    }
    let s = s.split(['/', '?', '#']).next().unwrap_or("").to_string();
    let s = s.rsplit_once('@').map(|(_, h)| h.to_string()).unwrap_or(s);
    let s = match s.rsplit_once(':') {
        Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) => h.to_string(),
        _ => s,
    };
    let s = s.trim_end_matches('.').to_string();
    // "www.example.com" means the whole domain: scan example.com (www is always checked too).
    let s = match s.strip_prefix("www.") {
        Some(rest) if rest.contains('.') => rest.to_string(),
        _ => s,
    };
    if s.is_empty() {
        return Err("Enter a domain, like example.com.".into());
    }
    if s.parse::<IpAddr>().is_ok() {
        return Err("Enter a domain name, not an IP address.".into());
    }
    if s.len() > 253 || !s.contains('.') {
        return Err("Enter a full domain, like example.com.".into());
    }
    for label in s.split('.') {
        let ok = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        if !ok {
            return Err(format!("\"{s}\" is not a valid domain name."));
        }
    }
    if s.rsplit('.').next().is_some_and(|tld| tld.chars().all(|c| c.is_ascii_digit())) {
        return Err(format!("\"{s}\" is not a valid domain name."));
    }
    Ok(s)
}

/// True for addresses on the public internet. The scanner never connects to anything else, so a hostname
/// that resolves to a private, loopback or reserved address is reported, not probed.
pub fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 carrier-grade NAT
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
                || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15 benchmarking
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(&IpAddr::V4(v4));
            }
            let seg0 = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg0 & 0xfe00) == 0xfc00 // unique local
                || (seg0 & 0xffc0) == 0xfe80 // link local
                || seg0 == 0x2001 && v6.segments()[1] == 0x0db8 // documentation
                || seg0 == 0x0100 && v6.segments()[1..4] == [0, 0, 0]) // discard-only 100::/64
        }
    }
}

/// True when `host` is `domain` or a subdomain of it.
pub fn in_domain(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_urls() {
        assert_eq!(normalize_domain(" HTTPS://WWW.Example.com:443/a?b ").unwrap(), "example.com");
        assert_eq!(normalize_domain("www.co.uk").unwrap(), "co.uk");
        assert_eq!(normalize_domain("api.example.com").unwrap(), "api.example.com");
        assert_eq!(normalize_domain("example.com.").unwrap(), "example.com");
    }

    #[test]
    fn rejects_bad_input() {
        assert!(normalize_domain("10.0.0.1").is_err());
        assert!(normalize_domain("localhost").is_err());
        assert!(normalize_domain("exa_mple.com").is_err());
        assert!(normalize_domain("").is_err());
        assert!(normalize_domain("1.2.3.4.5").is_err());
    }

    #[test]
    fn public_addresses() {
        for p in ["10.1.2.3", "127.0.0.1", "169.254.1.1", "100.64.1.1", "192.168.1.1", "::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1"] {
            assert!(!is_public(&p.parse().unwrap()), "{p}");
        }
        for p in ["1.1.1.1", "8.8.8.8", "2606:4700::1111"] {
            assert!(is_public(&p.parse().unwrap()), "{p}");
        }
    }

    #[test]
    fn subdomains() {
        assert!(in_domain("a.example.com", "example.com"));
        assert!(in_domain("example.com", "example.com"));
        assert!(!in_domain("badexample.com", "example.com"));
    }
}
