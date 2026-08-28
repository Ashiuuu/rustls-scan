use crate::models::Protocol;

#[derive(Debug, Clone)]
pub enum ServerHelloResponse {
    ServerHello {
        negotiated_protocol: Protocol,
        selected_cipher: u16,
        session_id: Vec<u8>,
        certificates_der: Vec<Vec<u8>>,
    },
    Alert {
        level: u8,
        description: u8,
    },
    Ssl2ServerHello {
        selected_ciphers: Vec<u32>,
        certificate_der: Option<Vec<u8>>,
    },
    Unknown,
}

pub fn build_ssl2_client_hello() -> Vec<u8> {
    let mut ciphers: Vec<u8> = Vec::new();
    // Standard SSLv2 3-byte cipher specs:
    // 0x010080: SSL_CK_RC4_128_WITH_MD5
    // 0x020080: SSL_CK_RC4_128_EXPORT40_WITH_MD5
    // 0x030080: SSL_CK_RC2_128_CBC_WITH_MD5
    // 0x040080: SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
    // 0x050080: SSL_CK_IDEA_128_CBC_WITH_MD5
    // 0x060040: SSL_CK_DES_64_CBC_WITH_MD5
    // 0x0700c0: SSL_CK_DES_192_EDE3_CBC_WITH_MD5
    let ssl2_ciphers = [
        0x010080u32,
        0x020080,
        0x030080,
        0x040080,
        0x050080,
        0x060040,
        0x0700c0,
    ];
    for c in ssl2_ciphers {
        ciphers.push((c >> 16) as u8);
        ciphers.push((c >> 8) as u8);
        ciphers.push(c as u8);
    }

    let challenge = [0x5au8; 16];
    let cipher_spec_len = ciphers.len() as u16;
    let session_id_len = 0u16;
    let challenge_len = challenge.len() as u16;

    // Body: msg_type (1) + version (2) + cipher_spec_len (2) + session_id_len (2) + challenge_len (2) + ciphers + challenge
    let body_len = 1 + 2 + 2 + 2 + 2 + ciphers.len() + challenge.len();
    let mut packet = Vec::with_capacity(2 + body_len);

    // 2-byte header with MSB set (0x8000 | body_len)
    let header = 0x8000 | (body_len as u16);
    packet.push((header >> 8) as u8);
    packet.push(header as u8);

    packet.push(0x01); // CLIENT_HELLO
    packet.push(0x00); // Version 0x0002
    packet.push(0x02);

    packet.push((cipher_spec_len >> 8) as u8);
    packet.push(cipher_spec_len as u8);

    packet.push((session_id_len >> 8) as u8);
    packet.push(session_id_len as u8);

    packet.push((challenge_len >> 8) as u8);
    packet.push(challenge_len as u8);

    packet.extend_from_slice(&ciphers);
    packet.extend_from_slice(&challenge);

    packet
}

pub fn build_client_hello(
    protocol: Protocol,
    ciphers: &[u16],
    server_name: Option<&str>,
) -> Vec<u8> {
    let mut body = Vec::new();

    // Client Version
    let (record_ver_hi, record_ver_lo, client_ver_hi, client_ver_lo) = match protocol {
        Protocol::Ssl2 => (0x00, 0x02, 0x00, 0x02),
        Protocol::Ssl3 => (0x03, 0x00, 0x03, 0x00),
        Protocol::Tls10 => (0x03, 0x01, 0x03, 0x01),
        Protocol::Tls11 => (0x03, 0x01, 0x03, 0x02),
        Protocol::Tls12 => (0x03, 0x01, 0x03, 0x03),
        Protocol::Tls13 => (0x03, 0x01, 0x03, 0x03), // RFC 8446 client_version is 0x0303
    };

    body.push(client_ver_hi);
    body.push(client_ver_lo);

    // Random: 32 bytes (4 bytes timestamp + 28 bytes)
    body.extend_from_slice(&[
        0x5f, 0x6e, 0x73, 0x82, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x24, 0x68,
        0xac, 0xe0,
    ]);

    // Session ID (32 bytes for TLS 1.3 middlebox compat, or 0 for SSLv3/TLS1.0-1.2)
    if protocol == Protocol::Tls13 {
        body.push(32);
        body.extend_from_slice(&[0x42u8; 32]);
    } else {
        body.push(0x00);
    }

    // Cipher Suites
    let cipher_len = (ciphers.len() * 2) as u16;
    body.push((cipher_len >> 8) as u8);
    body.push(cipher_len as u8);
    for &c in ciphers {
        body.push((c >> 8) as u8);
        body.push(c as u8);
    }

    // Compression Methods (1 method: 0x00 null)
    body.push(0x01);
    body.push(0x00);

    // Extensions (TLS 1.0+)
    if protocol != Protocol::Ssl3 && protocol != Protocol::Ssl2 {
        let mut extensions = Vec::new();

        // 1. SNI extension
        if let Some(sni) = server_name {
            let sni_bytes = sni.as_bytes();
            let mut sni_ext = Vec::new();
            let list_len = (sni_bytes.len() + 3) as u16;
            sni_ext.push((list_len >> 8) as u8);
            sni_ext.push(list_len as u8);
            sni_ext.push(0x00); // host_name
            sni_ext.push((sni_bytes.len() >> 8) as u8);
            sni_ext.push(sni_bytes.len() as u8);
            sni_ext.extend_from_slice(sni_bytes);

            // Extension type 0x0000
            extensions.push(0x00);
            extensions.push(0x00);
            extensions.push((sni_ext.len() >> 8) as u8);
            extensions.push(sni_ext.len() as u8);
            extensions.extend_from_slice(&sni_ext);
        }

        // 2. Supported Groups / Elliptic Curves (0x000a)
        let groups = [
            0x001du16, // X25519
            0x0017,   // secp256r1
            0x0018,   // secp384r1
            0x0019,   // secp521r1
        ];
        let mut groups_data = Vec::new();
        let groups_len = (groups.len() * 2) as u16;
        groups_data.push((groups_len >> 8) as u8);
        groups_data.push(groups_len as u8);
        for &g in &groups {
            groups_data.push((g >> 8) as u8);
            groups_data.push(g as u8);
        }
        extensions.push(0x00);
        extensions.push(0x0a);
        extensions.push((groups_data.len() >> 8) as u8);
        extensions.push(groups_data.len() as u8);
        extensions.extend_from_slice(&groups_data);

        // 3. EC Point Formats (0x000b)
        extensions.push(0x00);
        extensions.push(0x0b);
        extensions.push(0x00);
        extensions.push(0x02);
        extensions.push(0x01); // 1 format
        extensions.push(0x00); // uncompressed

        // 4. Signature Algorithms (0x000d - for TLS 1.2 and 1.3)
        if matches!(protocol, Protocol::Tls12 | Protocol::Tls13) {
            let sig_algs = [
                0x0403u16, // ecdsa_secp256r1_sha256
                0x0804,   // rsa_pss_rsae_sha256
                0x0401,   // rsa_pkcs1_sha256
                0x0503,   // ecdsa_secp384r1_sha384
                0x0805,   // rsa_pss_rsae_sha384
                0x0501,   // rsa_pkcs1_sha384
                0x0807,   // ed25519
                0x0601,   // rsa_pkcs1_sha512
                0x0201,   // rsa_pkcs1_sha1
            ];
            let mut sig_data = Vec::new();
            let sig_len = (sig_algs.len() * 2) as u16;
            sig_data.push((sig_len >> 8) as u8);
            sig_data.push(sig_len as u8);
            for &s in &sig_algs {
                sig_data.push((s >> 8) as u8);
                sig_data.push(s as u8);
            }
            extensions.push(0x00);
            extensions.push(0x0d);
            extensions.push((sig_data.len() >> 8) as u8);
            extensions.push(sig_data.len() as u8);
            extensions.extend_from_slice(&sig_data);
        }

        // 5. If TLS 1.3, add Supported Versions (0x002b) and Key Share (0x0033)
        if protocol == Protocol::Tls13 {
            // Supported Versions (0x002b)
            let mut supp_vers = Vec::new();
            supp_vers.push(0x02); // 2 bytes list
            supp_vers.push(0x03); // TLS 1.3 (0x0304)
            supp_vers.push(0x04);
            extensions.push(0x00);
            extensions.push(0x2b);
            extensions.push((supp_vers.len() >> 8) as u8);
            extensions.push(supp_vers.len() as u8);
            extensions.extend_from_slice(&supp_vers);

            // Key Share (0x0033)
            let mut key_share = Vec::new();
            // Client shares length (2 bytes): group (2) + key_exchange len (2) + key (32) = 36 bytes
            key_share.push(0x00);
            key_share.push(36);
            key_share.push(0x00);
            key_share.push(0x1d); // X25519
            key_share.push(0x00);
            key_share.push(32); // key length
            // Sample Curve25519 generator point / public key
            key_share.extend_from_slice(&[
                0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]);
            extensions.push(0x00);
            extensions.push(0x33);
            extensions.push((key_share.len() >> 8) as u8);
            extensions.push(key_share.len() as u8);
            extensions.extend_from_slice(&key_share);
        }

        // Add extensions length + extensions body
        let ext_len = extensions.len() as u16;
        body.push((ext_len >> 8) as u8);
        body.push(ext_len as u8);
        body.extend_from_slice(&extensions);
    }

    // Wrap in Handshake (0x01) and TLS Record (0x16)
    let body_len = body.len();
    let mut handshake = Vec::with_capacity(4 + body_len);
    handshake.push(0x01); // ClientHello
    handshake.push((body_len >> 16) as u8);
    handshake.push((body_len >> 8) as u8);
    handshake.push(body_len as u8);
    handshake.extend_from_slice(&body);

    let hs_len = handshake.len();
    let mut record = Vec::with_capacity(5 + hs_len);
    record.push(0x16); // Handshake
    record.push(record_ver_hi);
    record.push(record_ver_lo);
    record.push((hs_len >> 8) as u8);
    record.push(hs_len as u8);
    record.extend_from_slice(&handshake);

    record
}

pub fn parse_server_response(data: &[u8]) -> Option<ServerHelloResponse> {
    if data.is_empty() {
        return None;
    }

    // Check for SSLv2 ServerHello
    // SSLv2 header: bit 7 of byte 0 is 1, byte 2 is 0x04 (SERVER_HELLO)
    if (data[0] & 0x80) != 0 && data.len() >= 11 && data[2] == 0x04 {
        let cert_len = ((data[7] as usize) << 8) | (data[8] as usize);
        let ciphers_len = ((data[9] as usize) << 8) | (data[10] as usize);

        let mut offset = 11;
        let cert_der = if cert_len > 0 && data.len() >= offset + cert_len {
            let cert = data[offset..offset + cert_len].to_vec();
            offset += cert_len;
            Some(cert)
        } else {
            None
        };

        let mut selected_ciphers = Vec::new();
        if data.len() >= offset + ciphers_len {
            for chunk in data[offset..offset + ciphers_len].chunks_exact(3) {
                let id = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
                selected_ciphers.push(id);
            }
        }

        return Some(ServerHelloResponse::Ssl2ServerHello {
            selected_ciphers,
            certificate_der: cert_der,
        });
    }

    // Standard TLS Record Parsing
    let mut offset = 0;
    let mut server_hello: Option<(Protocol, u16, Vec<u8>)> = None;
    let mut certificates = Vec::new();

    while offset + 5 <= data.len() {
        let content_type = data[offset];
        let record_len = ((data[offset + 3] as usize) << 8) | (data[offset + 4] as usize);
        let record_start = offset + 5;
        let record_end = record_start + record_len;

        if record_end > data.len() {
            // Partial record
            break;
        }

        if content_type == 0x15 {
            // TLS Alert
            if record_len >= 2 {
                let level = data[record_start];
                let description = data[record_start + 1];
                return Some(ServerHelloResponse::Alert { level, description });
            }
        } else if content_type == 0x16 {
            // Handshake Record: iterate handshake messages inside this record
            let mut hs_offset = record_start;
            while hs_offset + 4 <= record_end {
                let hs_type = data[hs_offset];
                let hs_len = ((data[hs_offset + 1] as usize) << 16)
                    | ((data[hs_offset + 2] as usize) << 8)
                    | (data[hs_offset + 3] as usize);
                let hs_body_start = hs_offset + 4;
                let hs_body_end = hs_body_start + hs_len;

                if hs_body_end > record_end {
                    break;
                }

                if hs_type == 0x02 {
                    // ServerHello
                    if hs_len >= 38 {
                        let server_ver = ((data[hs_body_start] as u16) << 8)
                            | (data[hs_body_start + 1] as u16);
                        // Random: 32 bytes at hs_body_start + 2
                        let session_id_len = data[hs_body_start + 34] as usize;
                        let session_id_start = hs_body_start + 35;
                        let session_id_end = session_id_start + session_id_len;

                        if session_id_end + 3 <= hs_body_end {
                            let session_id = data[session_id_start..session_id_end].to_vec();
                            let cipher_id = ((data[session_id_end] as u16) << 8)
                                | (data[session_id_end + 1] as u16);
                            // Compression method at session_id_end + 2

                            // Check extensions (for TLS 1.3 supported_versions)
                            let mut negotiated_protocol = match server_ver {
                                0x0300 => Protocol::Ssl3,
                                0x0301 => Protocol::Tls10,
                                0x0302 => Protocol::Tls11,
                                0x0303 => Protocol::Tls12,
                                0x0304 => Protocol::Tls13,
                                _ => Protocol::Tls12,
                            };

                            let ext_offset = session_id_end + 3;
                            if ext_offset + 2 <= hs_body_end {
                                let ext_total_len = ((data[ext_offset] as usize) << 8)
                                    | (data[ext_offset + 1] as usize);
                                let mut curr_ext = ext_offset + 2;
                                let ext_end = (curr_ext + ext_total_len).min(hs_body_end);

                                while curr_ext + 4 <= ext_end {
                                    let ext_type = ((data[curr_ext] as u16) << 8)
                                        | (data[curr_ext + 1] as u16);
                                    let ext_item_len = ((data[curr_ext + 2] as usize) << 8)
                                        | (data[curr_ext + 3] as usize);
                                    let ext_data_start = curr_ext + 4;
                                    let ext_data_end = ext_data_start + ext_item_len;

                                    if ext_data_end > ext_end {
                                        break;
                                    }

                                    // supported_versions (0x002b)
                                    if ext_type == 0x002b && ext_item_len >= 2 {
                                        let ver = ((data[ext_data_start] as u16) << 8)
                                            | (data[ext_data_start + 1] as u16);
                                        if ver == 0x0304 {
                                            negotiated_protocol = Protocol::Tls13;
                                        }
                                    }

                                    curr_ext = ext_data_end;
                                }
                            }

                            server_hello =
                                Some((negotiated_protocol, cipher_id, session_id));
                        }
                    }
                } else if hs_type == 0x0b {
                    // Certificate (TLS 1.2 and earlier)
                    if hs_len >= 3 {
                        let certs_total_len = ((data[hs_body_start] as usize) << 16)
                            | ((data[hs_body_start + 1] as usize) << 8)
                            | (data[hs_body_start + 2] as usize);

                        let mut c_offset = hs_body_start + 3;
                        let c_end = (c_offset + certs_total_len).min(hs_body_end);

                        while c_offset + 3 <= c_end {
                            let cert_len = ((data[c_offset] as usize) << 16)
                                | ((data[c_offset + 1] as usize) << 8)
                                | (data[c_offset + 2] as usize);
                            let cert_start = c_offset + 3;
                            let cert_end = cert_start + cert_len;

                            if cert_end > c_end {
                                break;
                            }

                            certificates.push(data[cert_start..cert_end].to_vec());
                            c_offset = cert_end;
                        }
                    }
                }

                hs_offset = hs_body_end;
            }
        }

        offset = record_end;
    }

    if let Some((proto, cipher, session_id)) = server_hello {
        Some(ServerHelloResponse::ServerHello {
            negotiated_protocol: proto,
            selected_cipher: cipher,
            session_id,
            certificates_der: certificates,
        })
    } else if !certificates.is_empty() {
        Some(ServerHelloResponse::ServerHello {
            negotiated_protocol: Protocol::Tls12,
            selected_cipher: 0,
            session_id: Vec::new(),
            certificates_der: certificates,
        })
    } else {
        None
    }
}
