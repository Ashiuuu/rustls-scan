use rustssl_check::models::{Protocol, SecurityRating};
use rustssl_check::tls::cipher::{find_cipher, ALL_CIPHERS};
use rustssl_check::tls::packet::{build_client_hello, build_ssl2_client_hello, parse_server_response, ServerHelloResponse};

#[test]
fn test_cipher_database_integrity() {
    assert!(ALL_CIPHERS.len() > 30, "Cipher suite count should exceed 30");

    // Check TLS 1.3 ciphers
    let aes_128_gcm = find_cipher(0x1301).expect("TLS 1.3 AES-128-GCM must exist");
    assert_eq!(aes_128_gcm.iana_name, "TLS_AES_128_GCM_SHA256");
    assert_eq!(aes_128_gcm.rating, SecurityRating::Recommended);
    assert!(aes_128_gcm.is_aead);
    assert!(aes_128_gcm.forward_secrecy);

    // Check Insecure 3DES cipher
    let des3 = find_cipher(0x000a).expect("DES-CBC3-SHA must exist");
    assert_eq!(des3.rating, SecurityRating::Insecure);
    assert!(des3.is_obsolete);

    // Check Export RC4 cipher
    let exp_rc4 = find_cipher(0x0003).expect("EXP-RC4-MD5 must exist");
    assert_eq!(exp_rc4.rating, SecurityRating::Critical);
    assert!(exp_rc4.is_obsolete);

    // Check NULL cipher
    let null_sha = find_cipher(0x0002).expect("NULL-SHA must exist");
    assert_eq!(null_sha.rating, SecurityRating::Critical);
    assert_eq!(null_sha.key_bits, 0);
}

#[test]
fn test_protocol_metadata() {
    assert!(Protocol::Ssl2.is_obsolete());
    assert!(Protocol::Ssl3.is_obsolete());
    assert!(Protocol::Tls10.is_obsolete());
    assert!(Protocol::Tls11.is_obsolete());
    assert!(!Protocol::Tls12.is_obsolete());
    assert!(!Protocol::Tls13.is_obsolete());

    assert_eq!(Protocol::Ssl2.wire_version(), 0x0002);
    assert_eq!(Protocol::Tls13.wire_version(), 0x0304);
}

#[test]
fn test_ssl2_client_hello_builder() {
    let packet = build_ssl2_client_hello();
    assert!(!packet.is_empty());
    // SSLv2 record header starts with bit 7 set
    assert_ne!(packet[0] & 0x80, 0);
    // Msg type 0x01 = CLIENT_HELLO
    assert_eq!(packet[2], 0x01);
    // Version 0x0002
    assert_eq!(packet[3], 0x00);
    assert_eq!(packet[4], 0x02);
}

#[test]
fn test_tls12_client_hello_builder() {
    let ciphers = [0xc02f, 0xc030];
    let packet = build_client_hello(Protocol::Tls12, &ciphers, Some("example.com"));

    // Record header
    assert_eq!(packet[0], 0x16); // Handshake
    assert_eq!(packet[1], 0x03); // Record version 0x0301 (TLS 1.0)
    assert_eq!(packet[2], 0x01);

    // Handshake header
    assert_eq!(packet[5], 0x01); // ClientHello
    assert_eq!(packet[9], 0x03); // Client version 0x0303 (TLS 1.2)
    assert_eq!(packet[10], 0x03);
}

#[test]
fn test_tls13_client_hello_builder() {
    let ciphers = [0x1301, 0x1302, 0x1303];
    let packet = build_client_hello(Protocol::Tls13, &ciphers, Some("secure.example.com"));

    assert_eq!(packet[0], 0x16);
    assert_eq!(packet[5], 0x01); // ClientHello
    // Supported versions extension (0x002b) should be in packet
    let has_supp_ver = packet.windows(2).any(|w| w == [0x00, 0x2b]);
    assert!(has_supp_ver, "TLS 1.3 ClientHello must include supported_versions extension");
}

#[test]
fn test_server_alert_parser() {
    let alert_packet = vec![
        0x15, // ContentType: Alert
        0x03, 0x03, // Version 3.3
        0x00, 0x02, // Length 2
        0x02, // Fatal
        0x28, // handshake_failure (40)
    ];

    let resp = parse_server_response(&alert_packet);
    match resp {
        Some(ServerHelloResponse::Alert { level, description }) => {
            assert_eq!(level, 2);
            assert_eq!(description, 40);
        }
        _ => panic!("Expected alert response"),
    }
}

#[test]
fn test_cipher_vulnerability_classification() {
    let rec = find_cipher(0x1301).unwrap();
    assert!(!rec.is_vulnerable());

    let sec = find_cipher(0xc02f).unwrap();
    assert!(!sec.is_vulnerable());

    let weak_cbc = find_cipher(0xc027).unwrap();
    assert!(weak_cbc.is_vulnerable());

    let insec_3des = find_cipher(0x000a).unwrap();
    assert!(insec_3des.is_vulnerable());

    let crit_null = find_cipher(0x0002).unwrap();
    assert!(crit_null.is_vulnerable());
}

#[test]
fn test_scan_report_filter_vulnerable_ciphers() {
    use rustssl_check::models::{ProtocolCipherGroup, ScanReport};

    let c_rec = find_cipher(0x1301).unwrap();
    let c_weak = find_cipher(0xc027).unwrap();
    let c_3des = find_cipher(0x000a).unwrap();

    let mut report = ScanReport {
        target_host: "example.com".to_string(),
        target_port: 443,
        target_ip: "127.0.0.1".to_string(),
        rtt_ms: 10,
        protocols: vec![],
        protocol_ciphers: vec![
            ProtocolCipherGroup {
                protocol: Protocol::Tls13,
                ciphers: vec![c_rec],
            },
            ProtocolCipherGroup {
                protocol: Protocol::Tls12,
                ciphers: vec![c_rec, c_weak, c_3des],
            },
        ],
        supported_ciphers: vec![c_rec, c_weak, c_3des],
        rejected_ciphers_count: 50,
        server_cipher_preference: None,
        certificate: None,
        findings: vec![],
        overall_rating: SecurityRating::Weak,
        scan_duration_ms: 100,
    };

    report.filter_vulnerable_ciphers();

    // TLS 1.3 group had only recommended cipher, so it should be filtered out
    assert_eq!(report.protocol_ciphers.len(), 1);
    assert_eq!(report.protocol_ciphers[0].protocol, Protocol::Tls12);
    assert_eq!(report.protocol_ciphers[0].ciphers.len(), 2);
    assert_eq!(report.supported_ciphers.len(), 2);
    assert!(report.supported_ciphers.iter().all(|c| c.is_vulnerable()));
}
