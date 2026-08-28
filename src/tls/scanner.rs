use crate::models::{
    CertificateChainReport, CipherSuiteInfo, Protocol, ProtocolCipherGroup, ProtocolResult,
    ScanReport, SecurityRating, VulnerabilityFinding,
};
use crate::tls::cert::parse_and_validate_chain;
use crate::tls::cipher::{find_cipher, ALL_CIPHERS};
use crate::tls::packet::{build_client_hello, parse_server_response, ServerHelloResponse};
use crate::tls::protocol::probe_protocol;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

pub struct ScanOptions {
    pub target: String,
    pub port_override: Option<u16>,
    pub sni_override: Option<String>,
    pub timeout: Duration,
    pub concurrency: usize,
    pub protocols_only: bool,
    pub ciphers_only: bool,
    pub cert_only: bool,
}

pub async fn run_scan(options: ScanOptions) -> Result<ScanReport, String> {
    let scan_start = Instant::now();

    // 1. Parse target hostname/IP and port
    let (hostname, port) = parse_target(&options.target, options.port_override)?;
    let sni = options.sni_override.as_deref().unwrap_or(&hostname);

    // 2. DNS resolution
    let addr_str = format!("{}:{}", hostname, port);
    let socket_addrs = tokio::net::lookup_host(&addr_str)
        .await
        .map_err(|e| format!("Failed to resolve target '{}': {}", addr_str, e))?
        .collect::<Vec<SocketAddr>>();

    let target_addr = match socket_addrs.first() {
        Some(a) => *a,
        None => return Err(format!("No IP addresses found for target '{}'", hostname)),
    };

    // 3. Measure RTT with TCP connection
    let rtt_start = Instant::now();
    let rtt_test = timeout(options.timeout, TcpStream::connect(&target_addr)).await;
    let rtt_ms = match rtt_test {
        Ok(Ok(_)) => rtt_start.elapsed().as_millis() as u64,
        Ok(Err(e)) => return Err(format!("Failed to connect to {}: {}", target_addr, e)),
        Err(_) => return Err(format!("Connection timeout connecting to {}", target_addr)),
    };

    let mut protocol_results = Vec::new();
    let mut captured_certs: Option<Vec<Vec<u8>>> = None;

    // 4. Protocol scanning
    if !options.ciphers_only && !options.cert_only {
        for &proto in &Protocol::ALL {
            let (res, certs) = probe_protocol(&target_addr, Some(sni), proto, options.timeout).await;
            if certs.is_some() && captured_certs.is_none() {
                captured_certs = certs;
            }
            protocol_results.push(res);
        }
    } else {
        let (res12, certs12) =
            probe_protocol(&target_addr, Some(sni), Protocol::Tls12, options.timeout).await;
        if certs12.is_some() {
            captured_certs = certs12;
        }
        protocol_results.push(res12);
    }

    // 5. If certificates not captured yet (e.g. TLS 1.3 only), perform rustls handshake
    if captured_certs.is_none() && (!options.protocols_only && !options.ciphers_only) {
        captured_certs = fetch_certs_via_rustls(&hostname, &target_addr, options.timeout).await;
    }

    // Parse certificate chain
    let cert_report = if let Some(ref der_chain) = captured_certs {
        parse_and_validate_chain(der_chain, sni)
    } else {
        None
    };

    // 6. Cipher Suite Scanning per protocol
    let mut protocol_ciphers = Vec::new();
    let mut supported_ciphers: Vec<CipherSuiteInfo> = Vec::new();
    let mut rejected_ciphers_count = 0;
    let mut server_cipher_pref = None;

    if !options.protocols_only && !options.cert_only {
        // Collect protocols that are supported by the server
        let active_protocols: Vec<Protocol> = protocol_results
            .iter()
            .filter(|p| p.supported)
            .map(|p| p.protocol)
            .collect();

        // If no protocols marked supported (e.g. in ciphers_only mode), test all protocols in SCAN_ORDER
        let protos_to_test = if active_protocols.is_empty() {
            Protocol::SCAN_ORDER.to_vec()
        } else {
            Protocol::SCAN_ORDER
                .iter()
                .filter(|p| active_protocols.contains(p))
                .copied()
                .collect()
        };

        let mut seen_cipher_ids = HashSet::new();

        for proto in protos_to_test {
            let (ciphers_for_proto, rej) = scan_ciphers_for_protocol(
                &target_addr,
                Some(sni),
                proto,
                options.timeout,
                options.concurrency,
            )
            .await;

            rejected_ciphers_count += rej;

            for &c in &ciphers_for_proto {
                if seen_cipher_ids.insert(c.id) {
                    supported_ciphers.push(c);
                }
            }

            if !ciphers_for_proto.is_empty() {
                protocol_ciphers.push(ProtocolCipherGroup {
                    protocol: proto,
                    ciphers: ciphers_for_proto,
                });
            }
        }

        // Check server cipher preference
        if supported_ciphers.len() > 1 {
            server_cipher_pref =
                check_cipher_preference(&target_addr, Some(sni), &supported_ciphers, options.timeout)
                    .await;
        }
    }

    // 7. Security Assessment & Vulnerability Findings
    let findings = evaluate_vulnerabilities(&protocol_results, &supported_ciphers, &cert_report);
    let overall_rating = compute_overall_rating(&protocol_results, &supported_ciphers, &findings);

    let scan_duration_ms = scan_start.elapsed().as_millis() as u64;

    Ok(ScanReport {
        target_host: hostname,
        target_port: port,
        target_ip: target_addr.ip().to_string(),
        rtt_ms,
        protocols: protocol_results,
        protocol_ciphers,
        supported_ciphers,
        rejected_ciphers_count,
        server_cipher_preference: server_cipher_pref,
        certificate: cert_report,
        findings,
        overall_rating,
        scan_duration_ms,
    })
}

fn parse_target(raw: &str, port_override: Option<u16>) -> Result<(String, u16), String> {
    let s = raw.trim();
    let s = s.strip_prefix("https://").unwrap_or(s);
    let s = s.strip_prefix("http://").unwrap_or(s);
    let s = s.split('/').next().unwrap_or(s);

    if let Some(port) = port_override {
        let host = s.split(':').next().unwrap_or(s);
        return Ok((host.to_string(), port));
    }

    if let Some((host, port_str)) = s.split_once(':') {
        let port: u16 = port_str
            .parse()
            .map_err(|_| format!("Invalid port in target: '{}'", port_str))?;
        Ok((host.to_string(), port))
    } else {
        Ok((s.to_string(), 443))
    }
}

async fn scan_ciphers_for_protocol(
    addr: &SocketAddr,
    server_name: Option<&str>,
    protocol: Protocol,
    conn_timeout: Duration,
    concurrency: usize,
) -> (Vec<CipherSuiteInfo>, usize) {
    let candidates: Vec<CipherSuiteInfo> = ALL_CIPHERS
        .iter()
        .filter(|c| match protocol {
            Protocol::Tls13 => c.protocol_min == Protocol::Tls13,
            Protocol::Tls12 => c.protocol_min <= Protocol::Tls12 && c.protocol_min != Protocol::Tls13,
            Protocol::Tls11 => c.protocol_min <= Protocol::Tls11,
            Protocol::Tls10 => c.protocol_min <= Protocol::Tls10,
            Protocol::Ssl3 => c.protocol_min <= Protocol::Ssl3,
            Protocol::Ssl2 => c.protocol_min == Protocol::Ssl2 || c.protocol_min <= Protocol::Ssl3,
        })
        .copied()
        .collect();

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut handles = Vec::new();

    for cipher in candidates {
        let sem = semaphore.clone();
        let target = *addr;
        let sni = server_name.map(|s| s.to_string());
        let proto = protocol;

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.ok();
            probe_cipher_at_protocol(&target, sni.as_deref(), cipher, proto, conn_timeout).await
        });
        handles.push((cipher, handle));
    }

    let mut supported = Vec::new();
    let mut rejected = 0;

    for (cipher, handle) in handles {
        if let Ok(Ok(true)) = handle.await {
            supported.push(cipher);
        } else {
            rejected += 1;
        }
    }

    (supported, rejected)
}

async fn probe_cipher_at_protocol(
    addr: &SocketAddr,
    server_name: Option<&str>,
    cipher: CipherSuiteInfo,
    protocol: Protocol,
    conn_timeout: Duration,
) -> Result<bool, ()> {
    let stream = timeout(conn_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;

    let mut stream = stream;
    let packet = build_client_hello(protocol, &[cipher.id], server_name);

    timeout(conn_timeout, stream.write_all(&packet))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;

    let mut buf = vec![0u8; 4096];
    let n = timeout(conn_timeout, stream.read(&mut buf))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;

    if n > 0 {
        if let Some(resp) = parse_server_response(&buf[..n]) {
            match resp {
                ServerHelloResponse::ServerHello {
                    selected_cipher, ..
                } => {
                    if selected_cipher == cipher.id {
                        return Ok(true);
                    }
                }
                ServerHelloResponse::Ssl2ServerHello {
                    selected_ciphers, ..
                } => {
                    if selected_ciphers.contains(&(cipher.id as u32)) {
                        return Ok(true);
                    }
                }
                _ => {}
            }
        }
    }

    Ok(false)
}

async fn check_cipher_preference(
    addr: &SocketAddr,
    server_name: Option<&str>,
    supported_ciphers: &[CipherSuiteInfo],
    conn_timeout: Duration,
) -> Option<String> {
    if supported_ciphers.len() < 2 {
        return None;
    }

    let cipher_a = supported_ciphers[0].id;
    let cipher_b = supported_ciphers[1].id;

    let sel1 = probe_cipher_order(addr, server_name, &[cipher_a, cipher_b], conn_timeout).await?;
    let sel2 = probe_cipher_order(addr, server_name, &[cipher_b, cipher_a], conn_timeout).await?;

    if sel1 == sel2 {
        let pref_cipher = find_cipher(sel1).map(|c| c.iana_name).unwrap_or("Server choice");
        Some(format!("Server enforces cipher order (prefers {})", pref_cipher))
    } else {
        Some("Client order followed (server does NOT enforce cipher priority)".to_string())
    }
}

async fn probe_cipher_order(
    addr: &SocketAddr,
    server_name: Option<&str>,
    ciphers: &[u16],
    conn_timeout: Duration,
) -> Option<u16> {
    let mut stream = timeout(conn_timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let packet = build_client_hello(Protocol::Tls12, ciphers, server_name);
    timeout(conn_timeout, stream.write_all(&packet)).await.ok()?.ok()?;

    let mut buf = vec![0u8; 4096];
    let n = timeout(conn_timeout, stream.read(&mut buf)).await.ok()?.ok()?;

    if let Some(ServerHelloResponse::ServerHello { selected_cipher, .. }) = parse_server_response(&buf[..n]) {
        Some(selected_cipher)
    } else {
        None
    }
}

async fn fetch_certs_via_rustls(
    hostname: &str,
    addr: &SocketAddr,
    conn_timeout: Duration,
) -> Option<Vec<Vec<u8>>> {
    use std::sync::Mutex;

    #[derive(Debug)]
    struct CapturingVerifier {
        captured: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl rustls::client::danger::ServerCertVerifier for CapturingVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &rustls_pki_types::CertificateDer<'_>,
            intermediates: &[rustls_pki_types::CertificateDer<'_>],
            _server_name: &rustls_pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls_pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            let mut list = self.captured.lock().unwrap();
            list.push(end_entity.as_ref().to_vec());
            for c in intermediates {
                list.push(c.as_ref().to_vec());
            }
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls_pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls_pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::ED25519,
            ]
        }
    }

    let captured = Arc::new(Mutex::new(Vec::new()));
    let verifier = Arc::new(CapturingVerifier {
        captured: captured.clone(),
    });

    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let server_name = rustls_pki_types::ServerName::try_from(hostname.to_string()).ok()?;
    let connector = tokio_rustls_handshake(addr, &server_name, Arc::new(config), conn_timeout).await;

    if connector.is_ok() {
        let list = captured.lock().unwrap().clone();
        if !list.is_empty() {
            return Some(list);
        }
    }

    None
}

async fn tokio_rustls_handshake(
    addr: &SocketAddr,
    server_name: &rustls_pki_types::ServerName<'_>,
    config: Arc<rustls::ClientConfig>,
    conn_timeout: Duration,
) -> Result<(), ()> {
    let stream = timeout(conn_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;

    let mut conn = rustls::ClientConnection::new(config, server_name.to_owned()).map_err(|_| ())?;
    let mut std_stream = stream.into_std().map_err(|_| ())?;
    std_stream.set_nonblocking(false).map_err(|_| ())?;
    std_stream.set_read_timeout(Some(conn_timeout)).map_err(|_| ())?;
    std_stream.set_write_timeout(Some(conn_timeout)).map_err(|_| ())?;

    let mut tls_stream = rustls::Stream::new(&mut conn, &mut std_stream);
    let _ = std::io::Write::write_all(&mut tls_stream, b"HEAD / HTTP/1.1\r\n\r\n");
    Ok(())
}

fn evaluate_vulnerabilities(
    protocols: &[ProtocolResult],
    ciphers: &[CipherSuiteInfo],
    cert_report: &Option<CertificateChainReport>,
) -> Vec<VulnerabilityFinding> {
    let mut findings = Vec::new();

    for p in protocols {
        if p.supported {
            match p.protocol {
                Protocol::Ssl2 => findings.push(VulnerabilityFinding {
                    title: "SSLv2 Protocol Enabled".to_string(),
                    rating: SecurityRating::Critical,
                    description: "Server supports SSLv2, an obsolete protocol vulnerable to DROWN attack (CVE-2016-0800) and trivially cracked ciphers.".to_string(),
                    remediation: "Disable SSLv2 immediately across all web server configurations.".to_string(),
                }),
                Protocol::Ssl3 => findings.push(VulnerabilityFinding {
                    title: "SSLv3 Protocol Enabled (POODLE)".to_string(),
                    rating: SecurityRating::Critical,
                    description: "Server supports SSLv3, vulnerable to the POODLE attack (CVE-2014-3566) and insecure CBC padding.".to_string(),
                    remediation: "Disable SSLv3 across web server configurations.".to_string(),
                }),
                Protocol::Tls10 => findings.push(VulnerabilityFinding {
                    title: "TLS 1.0 Protocol Enabled (Deprecated)".to_string(),
                    rating: SecurityRating::Deprecated,
                    description: "TLS 1.0 was officially deprecated by RFC 8996 in 2021. Vulnerable to BEAST and Lucky 13 padding oracle attacks.".to_string(),
                    remediation: "Disable TLS 1.0 and require at least TLS 1.2.".to_string(),
                }),
                Protocol::Tls11 => findings.push(VulnerabilityFinding {
                    title: "TLS 1.1 Protocol Enabled (Deprecated)".to_string(),
                    rating: SecurityRating::Deprecated,
                    description: "TLS 1.1 was officially deprecated by RFC 8996 in 2021. Lacks modern AEAD cipher suite support.".to_string(),
                    remediation: "Disable TLS 1.1 and require at least TLS 1.2.".to_string(),
                }),
                _ => {}
            }
        }
    }

    let has_null = ciphers.iter().any(|c| c.encryption.contains("None") || c.key_bits == 0);
    if has_null {
        findings.push(VulnerabilityFinding {
            title: "NULL Ciphers Enabled (Unencrypted Traffic)".to_string(),
            rating: SecurityRating::Critical,
            description: "Server offers NULL encryption ciphers, allowing plaintext transmission of data without encryption.".to_string(),
            remediation: "Disable all NULL cipher suites in server configuration.".to_string(),
        });
    }

    let has_export = ciphers.iter().any(|c| c.rating == SecurityRating::Critical && c.key_bits <= 56 && c.key_bits > 0);
    if has_export {
        findings.push(VulnerabilityFinding {
            title: "Export-Grade Ciphers Enabled (FREAK / Logjam)".to_string(),
            rating: SecurityRating::Critical,
            description: "Server offers 40-bit / 56-bit export ciphers susceptible to factoring / brute-force attacks.".to_string(),
            remediation: "Disable all EXPORT ciphers.".to_string(),
        });
    }

    let has_3des = ciphers.iter().any(|c| c.encryption.contains("3DES") || c.encryption.contains("DES"));
    if has_3des {
        findings.push(VulnerabilityFinding {
            title: "3DES / DES Ciphers Enabled (Sweet32)".to_string(),
            rating: SecurityRating::Insecure,
            description: "3DES uses 64-bit block size vulnerable to Sweet32 collision attacks (CVE-2016-2183) over long sessions.".to_string(),
            remediation: "Remove 3DES/DES ciphers and transition to AES-GCM or ChaCha20-Poly1305.".to_string(),
        });
    }

    let has_rc4 = ciphers.iter().any(|c| c.encryption.contains("RC4"));
    if has_rc4 {
        findings.push(VulnerabilityFinding {
            title: "RC4 Stream Ciphers Enabled (RFC 7465)".to_string(),
            rating: SecurityRating::Insecure,
            description: "RC4 contains cryptographic biases (Bar Mitzvah, RC4 NOMORE) allowing plaintext recovery.".to_string(),
            remediation: "Prohibit RC4 cipher suites in accordance with RFC 7465.".to_string(),
        });
    }

    let has_anon = ciphers.iter().any(|c| c.key_exchange.contains("Anon"));
    if has_anon {
        findings.push(VulnerabilityFinding {
            title: "Anonymous Ciphers Enabled (Man-In-The-Middle)".to_string(),
            rating: SecurityRating::Critical,
            description: "Server accepts unauthenticated anonymous key exchange (ADH/AECDH), allowing trivial MITM attacks.".to_string(),
            remediation: "Disable all anonymous cipher suites.".to_string(),
        });
    }

    let has_static_rsa = ciphers.iter().any(|c| c.key_exchange == "RSA");
    if has_static_rsa {
        findings.push(VulnerabilityFinding {
            title: "Static RSA Key Exchange (No Forward Secrecy)".to_string(),
            rating: SecurityRating::Weak,
            description: "Static RSA key exchange does not provide Forward Secrecy (PFS). If the private key is compromised in the future, past recorded traffic can be decrypted.".to_string(),
            remediation: "Prefer ephemeral Diffie-Hellman (ECDHE / DHE) key exchange cipher suites.".to_string(),
        });
    }

    let has_cbc = ciphers.iter().any(|c| c.encryption.contains("CBC"));
    if has_cbc {
        findings.push(VulnerabilityFinding {
            title: "CBC-Mode Ciphers Enabled (Padding Oracle Risk)".to_string(),
            rating: SecurityRating::Weak,
            description: "Cipher Block Chaining (CBC) mode ciphers in TLS 1.0-1.2 are susceptible to timing and padding oracle attacks (Lucky 13, POODLE-TLS).".to_string(),
            remediation: "Prioritize AEAD ciphers (AES-GCM, ChaCha20-Poly1305) over CBC-mode ciphers.".to_string(),
        });
    }

    if let Some(cert_chain) = cert_report {
        let leaf = &cert_chain.leaf;
        if leaf.is_expired {
            findings.push(VulnerabilityFinding {
                title: "SSL/TLS Certificate is Expired".to_string(),
                rating: SecurityRating::Critical,
                description: format!("Certificate expired on {}. Browsers and clients will display security warnings.", leaf.not_after),
                remediation: "Renew and install an updated SSL/TLS certificate immediately.".to_string(),
            });
        } else if leaf.days_remaining <= 14 {
            findings.push(VulnerabilityFinding {
                title: format!("Certificate Expiring Soon ({} days remaining)", leaf.days_remaining),
                rating: SecurityRating::Weak,
                description: format!("Certificate will expire on {}.", leaf.not_after),
                remediation: "Schedule certificate renewal before expiration.".to_string(),
            });
        }

        if leaf.is_not_yet_valid {
            findings.push(VulnerabilityFinding {
                title: "Certificate Not Yet Valid".to_string(),
                rating: SecurityRating::Critical,
                description: format!("Certificate validity begins on {}.", leaf.not_before),
                remediation: "Ensure system clock is accurate and check certificate validity window.".to_string(),
            });
        }

        if leaf.public_key_bits > 0 && leaf.public_key_type.contains("RSA") && leaf.public_key_bits < 2048 {
            findings.push(VulnerabilityFinding {
                title: format!("Weak RSA Key Length ({} bits)", leaf.public_key_bits),
                rating: SecurityRating::Critical,
                description: "RSA keys below 2048 bits are considered cryptographically weak and factorable.".to_string(),
                remediation: "Regenerate certificate using at least RSA 2048-bit (or ECC P-256 / P-384) key.".to_string(),
            });
        }

        if leaf.sig_alg_rating == SecurityRating::Critical {
            findings.push(VulnerabilityFinding {
                title: format!("Insecure Certificate Signature Algorithm ({})", leaf.signature_algorithm),
                rating: SecurityRating::Critical,
                description: "Certificate was signed using MD5 or SHA-1, which are cryptographically broken.".to_string(),
                remediation: "Re-issue certificate with SHA-256 or SHA-384 signature algorithm.".to_string(),
            });
        }

        if let Some(false) = cert_chain.trust_valid {
            let err = cert_chain.trust_error.as_deref().unwrap_or("Untrusted certificate authority");
            findings.push(VulnerabilityFinding {
                title: "Certificate Trust Verification Failed".to_string(),
                rating: SecurityRating::Insecure,
                description: format!("Chain could not be verified against standard Mozilla Root CAs: {}", err),
                remediation: "Ensure full certificate chain (including intermediate CAs) is sent by the server, and certificate is issued by a recognized public CA.".to_string(),
            });
        }
    }

    findings
}

fn compute_overall_rating(
    protocols: &[ProtocolResult],
    ciphers: &[CipherSuiteInfo],
    findings: &[VulnerabilityFinding],
) -> SecurityRating {
    if findings.iter().any(|f| f.rating == SecurityRating::Critical) {
        return SecurityRating::Critical;
    }
    if findings.iter().any(|f| f.rating == SecurityRating::Insecure) {
        return SecurityRating::Insecure;
    }
    if findings.iter().any(|f| f.rating == SecurityRating::Deprecated) {
        return SecurityRating::Deprecated;
    }
    if findings.iter().any(|f| f.rating == SecurityRating::Weak) {
        return SecurityRating::Weak;
    }

    let tls13_on = protocols.iter().any(|p| p.protocol == Protocol::Tls13 && p.supported);
    let all_aead = !ciphers.is_empty() && ciphers.iter().all(|c| c.is_aead);

    if tls13_on && all_aead {
        SecurityRating::Recommended
    } else {
        SecurityRating::Secure
    }
}
