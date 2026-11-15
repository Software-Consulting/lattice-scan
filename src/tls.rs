//! Live TLS inspection of one hostname: handshake on port 443 (offering hybrid post-quantum key exchange), then
//! separate verification of the served chain against the Mozilla root set, and parsing of the leaf certificate.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use chrono::{TimeZone, Utc};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

use crate::ct::issuer_org;
use crate::report::CertInfo;

fn provider() -> Arc<CryptoProvider> {
    static P: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    P.get_or_init(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider())).clone()
}

/// Accepts any chain so the handshake completes and we can inspect what the server sends. Trust is checked
/// separately in `verify_chain`; handshake signatures are still verified properly.
#[derive(Debug)]
struct Inspect(Arc<CryptoProvider>);

impl ServerCertVerifier for Inspect {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn connector() -> TlsConnector {
    static C: OnceLock<TlsConnector> = OnceLock::new();
    C.get_or_init(|| {
        let p = provider();
        let cfg = ClientConfig::builder_with_provider(p.clone())
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Inspect(p)))
            .with_no_client_auth();
        TlsConnector::from(Arc::new(cfg))
    })
    .clone()
}

fn webpki() -> Arc<WebPkiServerVerifier> {
    static V: OnceLock<Arc<WebPkiServerVerifier>> = OnceLock::new();
    V.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider()).build().expect("verifier")
    })
    .clone()
}

pub struct TlsOutcome {
    pub tls_version: String,
    pub cipher_suite: String,
    pub key_exchange: Option<String>,
    pub chain: Vec<CertificateDer<'static>>,
}

pub async fn handshake(host: &str, ip: IpAddr, limit: Duration) -> Result<TlsOutcome, (String, String)> {
    let name = ServerName::try_from(host.to_string()).map_err(|e| ("handshake_failed".to_string(), e.to_string()))?;
    let tcp = timeout(limit, TcpStream::connect(SocketAddr::new(ip, 443)))
        .await
        .map_err(|_| ("connect_failed".to_string(), "No answer on port 443.".to_string()))?
        .map_err(|e| ("connect_failed".to_string(), format!("Port 443 refused the connection ({e}).")))?;
    let tls = timeout(limit, connector().connect(name, tcp))
        .await
        .map_err(|_| ("handshake_failed".to_string(), "TLS handshake timed out.".to_string()))?
        .map_err(|e| ("handshake_failed".to_string(), format!("TLS handshake failed: {e}.")))?;
    let (_, conn) = tls.get_ref();
    Ok(TlsOutcome {
        tls_version: conn.protocol_version().map(|v| format!("{v:?}").replace("TLSv1_", "TLS 1.")).unwrap_or_default(),
        cipher_suite: conn.negotiated_cipher_suite().map(|s| format!("{:?}", s.suite())).unwrap_or_default(),
        key_exchange: conn.negotiated_key_exchange_group().map(|g| format!("{:?}", g.name())),
        chain: conn.peer_certificates().map(|c| c.iter().map(|d| d.clone().into_owned()).collect()).unwrap_or_default(),
    })
}

/// None when the chain is publicly trusted and valid for `host`, otherwise a short reason id and message.
pub fn verify_chain(host: &str, chain: &[CertificateDer<'static>]) -> Option<(String, String)> {
    let Some((leaf, rest)) = chain.split_first() else {
        return Some(("no_certificate".into(), "The server sent no certificate.".into()));
    };
    let name = match ServerName::try_from(host.to_string()) {
        Ok(n) => n,
        Err(e) => return Some(("invalid".into(), e.to_string())),
    };
    match webpki().verify_server_cert(leaf, rest, &name, &[], UnixTime::now()) {
        Ok(_) => None,
        Err(e) => {
            let s = format!("{e:?}");
            let id = if s.contains("Expired") {
                "expired"
            } else if s.contains("NotValidForName") {
                "name_mismatch"
            } else if s.contains("UnknownIssuer") {
                "untrusted_issuer"
            } else if s.contains("NotValidYet") {
                "not_yet_valid"
            } else if s.contains("Revoked") {
                "revoked"
            } else {
                "invalid"
            };
            Some((id.into(), e.to_string()))
        }
    }
}

fn sig_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.11" => "SHA-256 with RSA",
        "1.2.840.113549.1.1.12" => "SHA-384 with RSA",
        "1.2.840.113549.1.1.13" => "SHA-512 with RSA",
        "1.2.840.113549.1.1.5" => "SHA-1 with RSA",
        "1.2.840.113549.1.1.10" => "RSA-PSS",
        "1.2.840.10045.4.3.2" => "ECDSA with SHA-256",
        "1.2.840.10045.4.3.3" => "ECDSA with SHA-384",
        "1.2.840.10045.4.3.4" => "ECDSA with SHA-512",
        "1.2.840.10045.4.1" => "ECDSA with SHA-1",
        "1.3.101.112" => "Ed25519",
        "2.16.840.1.101.3.4.3.17" => "ML-DSA-44",
        "2.16.840.1.101.3.4.3.18" => "ML-DSA-65",
        "2.16.840.1.101.3.4.3.19" => "ML-DSA-87",
        other => return other.to_string(),
    }
    .to_string()
}

fn curve_name(oid: &str) -> &str {
    match oid {
        "1.2.840.10045.3.1.7" => "P-256",
        "1.3.132.0.34" => "P-384",
        "1.3.132.0.35" => "P-521",
        _ => "curve",
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

pub fn subject_cn(der: &CertificateDer<'_>) -> String {
    X509Certificate::from_der(der.as_ref())
        .ok()
        .and_then(|(_, c)| c.subject().iter_common_name().next().and_then(|a| a.as_str().ok()).map(String::from))
        .unwrap_or_else(|| "(no common name)".into())
}

pub fn parse_leaf(der: &CertificateDer<'_>) -> Option<CertInfo> {
    let (_, c) = X509Certificate::from_der(der.as_ref()).ok()?;
    let nb = Utc.timestamp_opt(c.validity().not_before.timestamp(), 0).single()?;
    let na = Utc.timestamp_opt(c.validity().not_after.timestamp(), 0).single()?;
    let sans = match c.subject_alternative_name() {
        Ok(Some(ext)) => ext
            .value
            .general_names
            .iter()
            .filter_map(|g| match g {
                GeneralName::DNSName(d) => Some(d.to_string()),
                _ => None,
            })
            .collect(),
        _ => vec![],
    };
    let spki = c.public_key();
    let alg = spki.algorithm.algorithm.to_id_string();
    let key = match spki.parsed() {
        Ok(x509_parser::public_key::PublicKey::RSA(r)) => format!("RSA {}", r.key_size()),
        Ok(x509_parser::public_key::PublicKey::EC(_)) => {
            let curve = spki.algorithm.parameters.as_ref().and_then(|p| p.as_oid().ok()).map(|o| o.to_id_string()).unwrap_or_default();
            format!("EC {}", curve_name(&curve))
        }
        _ if alg == "1.3.101.112" => "Ed25519".to_string(),
        _ => sig_name(&alg),
    };
    let digest = aws_lc_rs_sha256(der.as_ref());
    let subject_cn: Option<String> = c.subject().iter_common_name().next().and_then(|a| a.as_str().ok()).map(String::from);
    Some(CertInfo {
        subject_cn,
        sans,
        issuer: issuer_org(&c.issuer().to_string()),
        not_before: nb,
        not_after: na,
        lifetime_days: (na - nb).num_days(),
        days_remaining: (na - Utc::now()).num_days(),
        key,
        signature_algorithm: sig_name(&c.signature_algorithm.algorithm.to_id_string()),
        serial: c.raw_serial_as_string().to_uppercase(),
        sha256_fingerprint: hex(&digest),
    })
}

fn aws_lc_rs_sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).to_vec()
}
