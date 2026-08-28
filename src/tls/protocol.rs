use crate::models::{Protocol, ProtocolResult};
use crate::tls::cipher::ALL_CIPHERS;
use crate::tls::packet::{build_client_hello, build_ssl2_client_hello, parse_server_response, ServerHelloResponse};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub async fn probe_protocol(
    addr: &SocketAddr,
    server_name: Option<&str>,
    protocol: Protocol,
    conn_timeout: Duration,
) -> (ProtocolResult, Option<Vec<Vec<u8>>>) {
    let result = match protocol {
        Protocol::Ssl2 => probe_ssl2(addr, conn_timeout).await,
        _ => probe_tls(addr, server_name, protocol, conn_timeout).await,
    };

    let (supported, certs) = match result {
        Ok((sup, certs)) => (sup, certs),
        Err(_) => (false, None),
    };

    let rating = if supported {
        protocol.default_rating()
    } else {
        crate::models::SecurityRating::Recommended
    };

    (
        ProtocolResult {
            protocol,
            supported,
            rating,
        },
        certs,
    )
}

async fn probe_ssl2(
    addr: &SocketAddr,
    conn_timeout: Duration,
) -> Result<(bool, Option<Vec<Vec<u8>>>), ()> {
    let connect_future = TcpStream::connect(addr);
    let mut stream = timeout(conn_timeout, connect_future)
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;

    let packet = build_ssl2_client_hello();
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
                ServerHelloResponse::Ssl2ServerHello { certificate_der, .. } => {
                    let certs = certificate_der.map(|c| vec![c]);
                    return Ok((true, certs));
                }
                ServerHelloResponse::Alert { .. } => return Ok((false, None)),
                _ => {}
            }
        }
    }

    Ok((false, None))
}

async fn probe_tls(
    addr: &SocketAddr,
    server_name: Option<&str>,
    protocol: Protocol,
    conn_timeout: Duration,
) -> Result<(bool, Option<Vec<Vec<u8>>>), ()> {
    let connect_future = TcpStream::connect(addr);
    let mut stream = timeout(conn_timeout, connect_future)
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;

    // Gather candidate ciphers for this protocol
    let ciphers: Vec<u16> = ALL_CIPHERS
        .iter()
        .filter(|c| match protocol {
            Protocol::Tls13 => c.protocol_min == Protocol::Tls13,
            Protocol::Tls12 => c.protocol_min <= Protocol::Tls12,
            Protocol::Tls11 => c.protocol_min <= Protocol::Tls11,
            Protocol::Tls10 => c.protocol_min <= Protocol::Tls10,
            Protocol::Ssl3 => c.protocol_min <= Protocol::Ssl3,
            _ => true,
        })
        .map(|c| c.id)
        .collect();

    let packet = build_client_hello(protocol, &ciphers, server_name);
    timeout(conn_timeout, stream.write_all(&packet))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;

    let mut buf = vec![0u8; 8192];
    let mut total_read = 0;

    // Read initial response
    let n = timeout(conn_timeout, stream.read(&mut buf))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
    total_read += n;

    // Try reading more to get complete certificate chain if needed
    if total_read > 0 && total_read < 8192 {
        let _ = timeout(Duration::from_millis(150), stream.read(&mut buf[total_read..])).await;
    }

    if let Some(resp) = parse_server_response(&buf[..total_read]) {
        match resp {
            ServerHelloResponse::ServerHello {
                negotiated_protocol,
                certificates_der,
                ..
            } => {
                let is_match = match protocol {
                    Protocol::Tls13 => negotiated_protocol == Protocol::Tls13,
                    Protocol::Tls12 => negotiated_protocol == Protocol::Tls12,
                    Protocol::Tls11 => negotiated_protocol == Protocol::Tls11,
                    Protocol::Tls10 => negotiated_protocol == Protocol::Tls10,
                    Protocol::Ssl3 => negotiated_protocol == Protocol::Ssl3,
                    _ => false,
                };
                let certs = if !certificates_der.is_empty() {
                    Some(certificates_der)
                } else {
                    None
                };
                return Ok((is_match, certs));
            }
            ServerHelloResponse::Alert { .. } => return Ok((false, None)),
            _ => {}
        }
    }

    Ok((false, None))
}
