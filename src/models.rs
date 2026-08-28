use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Ssl2,
    Ssl3,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

impl Protocol {
    pub const ALL: [Protocol; 6] = [
        Protocol::Ssl2,
        Protocol::Ssl3,
        Protocol::Tls10,
        Protocol::Tls11,
        Protocol::Tls12,
        Protocol::Tls13,
    ];

    pub const SCAN_ORDER: [Protocol; 6] = [
        Protocol::Tls13,
        Protocol::Tls12,
        Protocol::Tls11,
        Protocol::Tls10,
        Protocol::Ssl3,
        Protocol::Ssl2,
    ];

    pub fn name(&self) -> &'static str {
        match self {
            Protocol::Ssl2 => "SSLv2",
            Protocol::Ssl3 => "SSLv3",
            Protocol::Tls10 => "TLS 1.0",
            Protocol::Tls11 => "TLS 1.1",
            Protocol::Tls12 => "TLS 1.2",
            Protocol::Tls13 => "TLS 1.3",
        }
    }

    pub fn wire_version(&self) -> u16 {
        match self {
            Protocol::Ssl2 => 0x0002,
            Protocol::Ssl3 => 0x0300,
            Protocol::Tls10 => 0x0301,
            Protocol::Tls11 => 0x0302,
            Protocol::Tls12 => 0x0303,
            Protocol::Tls13 => 0x0304,
        }
    }

    pub fn is_obsolete(&self) -> bool {
        matches!(
            self,
            Protocol::Ssl2 | Protocol::Ssl3 | Protocol::Tls10 | Protocol::Tls11
        )
    }

    pub fn default_rating(&self) -> SecurityRating {
        match self {
            Protocol::Ssl2 | Protocol::Ssl3 => SecurityRating::Insecure,
            Protocol::Tls10 | Protocol::Tls11 => SecurityRating::Deprecated,
            Protocol::Tls12 => SecurityRating::Secure,
            Protocol::Tls13 => SecurityRating::Recommended,
        }
    }

    pub fn security_notes(&self) -> &'static str {
        match self {
            Protocol::Ssl2 => "Vulnerable to DROWN, broken ciphers, insecure MAC (RFC 6176 prohibited)",
            Protocol::Ssl3 => "Vulnerable to POODLE, insecure MAC, weak CBC (RFC 7568 prohibited)",
            Protocol::Tls10 => "Deprecated (RFC 8996), vulnerable to BEAST / Lucky13, outdated ciphers",
            Protocol::Tls11 => "Deprecated (RFC 8996), weak SHA-1/MD5 PRF, lacks modern AEAD",
            Protocol::Tls12 => "Standard protocol, secure when modern AEAD/PFS ciphers are configured",
            Protocol::Tls13 => "Modern recommended protocol, mandatory PFS, robust AEAD ciphers only (RFC 8446)",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SecurityRating {
    Recommended,
    Secure,
    Deprecated,
    Weak,
    Insecure,
    Critical,
}

impl SecurityRating {
    pub fn badge_text(&self) -> &'static str {
        match self {
            SecurityRating::Recommended => "RECOMMENDED",
            SecurityRating::Secure => "SECURE",
            SecurityRating::Deprecated => "DEPRECATED",
            SecurityRating::Weak => "WEAK",
            SecurityRating::Insecure => "INSECURE",
            SecurityRating::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolResult {
    pub protocol: Protocol,
    pub supported: bool,
    pub rating: SecurityRating,
    pub notes: String,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct CipherSuiteInfo {
    pub id: u16,
    pub iana_name: &'static str,
    pub openssl_name: &'static str,
    pub protocol_min: Protocol,
    pub key_exchange: &'static str,
    pub encryption: &'static str,
    pub key_bits: u16,
    pub mac: &'static str,
    pub forward_secrecy: bool,
    pub is_aead: bool,
    pub is_obsolete: bool,
    pub rating: SecurityRating,
    pub vulnerability_note: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtocolCipherGroup {
    pub protocol: Protocol,
    pub ciphers: Vec<CipherSuiteInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject_cn: Option<String>,
    pub subject_o: Option<String>,
    pub subject_c: Option<String>,
    pub subject_dn: String,
    pub issuer_cn: Option<String>,
    pub issuer_o: Option<String>,
    pub issuer_c: Option<String>,
    pub issuer_dn: String,
    pub sans: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub days_remaining: i64,
    pub is_expired: bool,
    pub is_not_yet_valid: bool,
    pub signature_algorithm: String,
    pub sig_alg_rating: SecurityRating,
    pub public_key_type: String,
    pub public_key_bits: u32,
    pub key_rating: SecurityRating,
    pub serial_number: String,
    pub sha256_fingerprint: String,
    pub sha1_fingerprint: String,
    pub is_self_signed: bool,
    pub is_ca: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateChainReport {
    pub leaf: CertificateInfo,
    pub intermediates: Vec<CertificateInfo>,
    pub trust_valid: Option<bool>,
    pub trust_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFinding {
    pub title: String,
    pub rating: SecurityRating,
    pub description: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub target_host: String,
    pub target_port: u16,
    pub target_ip: String,
    pub rtt_ms: u64,
    pub protocols: Vec<ProtocolResult>,
    pub protocol_ciphers: Vec<ProtocolCipherGroup>,
    pub supported_ciphers: Vec<CipherSuiteInfo>,
    pub rejected_ciphers_count: usize,
    pub server_cipher_preference: Option<String>,
    pub certificate: Option<CertificateChainReport>,
    pub findings: Vec<VulnerabilityFinding>,
    pub overall_rating: SecurityRating,
    pub scan_duration_ms: u64,
}
