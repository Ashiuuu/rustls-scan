use crate::models::{CertificateChainReport, CertificateInfo, SecurityRating};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use webpki::EndEntityCert;
use x509_parser::prelude::*;

pub fn parse_der_certificate(der: &[u8]) -> Result<CertificateInfo, String> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| format!("Failed to parse X.509 certificate: {}", e))?;

    let subject_dn = cert.subject().to_string();
    let mut subject_cn = None;
    let mut subject_o = None;
    let mut subject_c = None;

    for rdn in cert.subject().iter() {
        for attr in rdn.iter() {
            if let Ok(val) = attr.as_str() {
                match attr.attr_type().to_string().as_str() {
                    "2.5.4.3" => subject_cn = Some(val.to_string()),
                    "2.5.4.10" => subject_o = Some(val.to_string()),
                    "2.5.4.6" => subject_c = Some(val.to_string()),
                    _ => {}
                }
            }
        }
    }

    let issuer_dn = cert.issuer().to_string();
    let mut issuer_cn = None;
    let mut issuer_o = None;
    let mut issuer_c = None;

    for rdn in cert.issuer().iter() {
        for attr in rdn.iter() {
            if let Ok(val) = attr.as_str() {
                match attr.attr_type().to_string().as_str() {
                    "2.5.4.3" => issuer_cn = Some(val.to_string()),
                    "2.5.4.10" => issuer_o = Some(val.to_string()),
                    "2.5.4.6" => issuer_c = Some(val.to_string()),
                    _ => {}
                }
            }
        }
    }

    // SANs
    let mut sans = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for general_name in &ext.value.general_names {
            match general_name {
                GeneralName::DNSName(dns) => sans.push(dns.to_string()),
                GeneralName::IPAddress(ip) => {
                    if ip.len() == 4 {
                        sans.push(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
                    } else if ip.len() == 16 {
                        sans.push(format!("{:x?}", ip));
                    }
                }
                GeneralName::RFC822Name(email) => sans.push(format!("email:{}", email)),
                GeneralName::URI(uri) => sans.push(format!("URI:{}", uri)),
                _ => {}
            }
        }
    }

    // Validity
    let not_before_ts = cert.validity().not_before.timestamp();
    let not_after_ts = cert.validity().not_after.timestamp();

    let not_before_str = cert.validity().not_before.to_rfc2822().unwrap_or_else(|_| "Unknown".to_string());
    let not_after_str = cert.validity().not_after.to_rfc2822().unwrap_or_else(|_| "Unknown".to_string());

    let now_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let is_expired = now_ts > not_after_ts;
    let is_not_yet_valid = now_ts < not_before_ts;
    let days_remaining = (not_after_ts - now_ts) / 86400;

    // Signature Algorithm
    let sig_alg_oid = cert.signature_algorithm.algorithm.to_string();
    let sig_alg_name = match sig_alg_oid.as_str() {
        "1.2.840.113549.1.1.11" => "SHA256withRSA",
        "1.2.840.113549.1.1.12" => "SHA384withRSA",
        "1.2.840.113549.1.1.13" => "SHA512withRSA",
        "1.2.840.113549.1.1.5" => "SHA1withRSA (Insecure)",
        "1.2.840.113549.1.1.4" => "MD5withRSA (Broken)",
        "1.2.840.10045.4.3.2" => "ECDSA-with-SHA256",
        "1.2.840.10045.4.3.3" => "ECDSA-with-SHA384",
        "1.2.840.10045.4.3.4" => "ECDSA-with-SHA512",
        "1.3.101.112" => "Ed25519",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        other => other,
    };

    let sig_alg_rating = if sig_alg_name.contains("SHA1") || sig_alg_name.contains("MD5") {
        SecurityRating::Critical
    } else {
        SecurityRating::Recommended
    };

    // Public Key Info
    let spki = cert.public_key();
    let pk_oid = spki.algorithm.algorithm.to_string();
    let (pk_type, pk_bits, key_rating) = match pk_oid.as_str() {
        "1.2.840.113549.1.1.1" => {
            // RSA
            let raw_key = spki.raw;
            let bits = if raw_key.len() > 500 {
                4096
            } else if raw_key.len() > 350 {
                3072
            } else if raw_key.len() > 250 {
                2048
            } else if raw_key.len() > 120 {
                1024
            } else {
                512
            };
            let rating = if bits < 2048 {
                SecurityRating::Critical
            } else if bits == 2048 {
                SecurityRating::Secure
            } else {
                SecurityRating::Recommended
            };
            (format!("RSA {} bit", bits), bits as u32, rating)
        }
        "1.2.840.10045.2.1" => {
            // ECC
            let bits = match spki.algorithm.parameters.as_ref().and_then(|p| p.as_oid().ok()) {
                Some(oid) if oid.to_string() == "1.2.840.10045.3.1.7" => 256,
                Some(oid) if oid.to_string() == "1.3.132.0.34" => 384,
                Some(oid) if oid.to_string() == "1.3.132.0.35" => 521,
                _ => 256,
            };
            (format!("ECDSA {} bit (P-{})", bits, bits), bits, SecurityRating::Recommended)
        }
        "1.3.101.112" => ("Ed25519 256 bit".to_string(), 256, SecurityRating::Recommended),
        _ => ("Unknown Key Type".to_string(), 0, SecurityRating::Weak),
    };

    // Fingerprints
    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(der);
    let sha256_bytes = sha256_hasher.finalize();
    let sha256_fingerprint = sha256_bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":");

    let mut sha1_hasher = Sha1::new();
    sha1_hasher.update(der);
    let sha1_bytes = sha1_hasher.finalize();
    let sha1_fingerprint = sha1_bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":");

    // Serial number
    let serial_number = cert.raw_serial()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":");

    let is_self_signed = cert.subject() == cert.issuer();
    let is_ca = cert.basic_constraints()
        .map(|bc| bc.map(|b| b.value.ca).unwrap_or(false))
        .unwrap_or(false);

    Ok(CertificateInfo {
        subject_cn,
        subject_o,
        subject_c,
        subject_dn,
        issuer_cn,
        issuer_o,
        issuer_c,
        issuer_dn,
        sans,
        not_before: not_before_str,
        not_after: not_after_str,
        days_remaining,
        is_expired,
        is_not_yet_valid,
        signature_algorithm: sig_alg_name.to_string(),
        sig_alg_rating,
        public_key_type: pk_type,
        public_key_bits: pk_bits,
        key_rating,
        serial_number,
        sha256_fingerprint,
        sha1_fingerprint,
        is_self_signed,
        is_ca,
    })
}

pub fn parse_and_validate_chain(
    der_certs: &[Vec<u8>],
    server_name: &str,
) -> Option<CertificateChainReport> {
    if der_certs.is_empty() {
        return None;
    }

    let leaf_der = &der_certs[0];
    let leaf_info = match parse_der_certificate(leaf_der) {
        Ok(info) => info,
        Err(_) => return None,
    };

    let mut intermediates = Vec::new();
    for der in &der_certs[1..] {
        if let Ok(info) = parse_der_certificate(der) {
            intermediates.push(info);
        }
    }

    // Validate chain trust against Mozilla root store via webpki
    let trust_valid;
    let mut trust_error = None;

    let end_entity = rustls_pki_types::CertificateDer::from_slice(leaf_der);
    {
        let intermediate_certs: Vec<rustls_pki_types::CertificateDer> = der_certs[1..]
            .iter()
            .map(|d| rustls_pki_types::CertificateDer::from_slice(d).into_owned())
            .collect();

        let trust_anchors: Vec<rustls_pki_types::TrustAnchor> = webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned()
            .collect();

        let parsed_end_entity = EndEntityCert::try_from(&end_entity);

        match parsed_end_entity {
            Ok(ee) => {
                let now = rustls_pki_types::UnixTime::now();
                let sig_algs = rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms
                    .all;
                let verify_res = ee.verify_for_usage(
                    sig_algs,
                    &trust_anchors,
                    &intermediate_certs,
                    now,
                    webpki::KeyUsage::server_auth(),
                    None,
                    None,
                );

                match verify_res {
                    Ok(_) => {
                        // Check DNS name match if server_name is a hostname
                        if let Ok(sn) = rustls_pki_types::ServerName::try_from(server_name.to_string()) {
                            match ee.verify_is_valid_for_subject_name(&sn) {
                                Ok(_) => {
                                    trust_valid = true;
                                }
                                Err(e) => {
                                    trust_valid = false;
                                    trust_error = Some(format!("Hostname mismatch: {}", e));
                                }
                            }
                        } else {
                            trust_valid = true;
                        }
                    }
                    Err(e) => {
                        trust_valid = false;
                        trust_error = Some(format!("Trust validation failed: {}", e));
                    }
                }
            }
            Err(e) => {
                trust_valid = false;
                trust_error = Some(format!("Certificate parse error for verification: {}", e));
            }
        }
    }

    Some(CertificateChainReport {
        leaf: leaf_info,
        intermediates,
        trust_valid: Some(trust_valid),
        trust_error,
    })
}
