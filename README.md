# lattice-scan

Scan a domain's public TLS certificates from the command line or from Rust.

- Finds hostnames from Certificate Transparency logs (SSLMate Cert Spotter, crt.sh as fallback).
- Connects on port 443 with rustls, offering TLS 1.3 and the hybrid post-quantum key exchange X25519MLKEM768, and
  records what each server negotiates.
- Verifies the served chain against the Mozilla root store and reads the leaf certificate: names, issuer, lifetime,
  key and signature algorithm.
- Checks CAA records and the HSTS header, then grades the domain A to F.
- Flags certificates issued for more than 100 days: from March 15, 2027 publicly trusted certificates may last at
  most 100 days, and from March 15, 2029 at most 47 (CA/Browser Forum Ballot SC-081v3).

It never connects to private, loopback or reserved addresses.

## Install

```bash
cargo install lattice-scan
```

## Use

```bash
lattice-scan example.com                 # readable report
lattice-scan example.com --json          # full report as JSON
lattice-scan example.com --no-ct         # the domain and www only
lattice-scan example.com --fail-on high  # exit 2 on any high or critical finding (for CI)
```

## Library

```rust
let report = lattice_scan::scan("example.com", &lattice_scan::ScanOptions::default()).await?;
println!("{} {}", report.domain, report.grade);
```

The hosted version, with shareable reports, is at [latticepki.com](https://latticepki.com).

## License

Apache License 2.0. See [LICENSE](LICENSE).
