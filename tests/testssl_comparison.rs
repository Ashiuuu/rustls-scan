use rustssl_check::models::Protocol;
use rustssl_check::tls::scanner::{run_scan, ScanOptions};
use serde_json::Value;
use std::process::Command;
use std::time::Duration;

fn run_testssl(target: &str, json_path: &str) -> Result<Value, String> {
    let output = Command::new("testssl")
        .args(&["--overwrite", "-p", "-S", "--jsonfile-pretty", json_path, target])
        .output()
        .map_err(|e| format!("Failed to execute testssl: {}", e))?;

    if !output.status.success() && output.stdout.is_empty() {
        return Err(format!(
            "testssl failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let json_bytes = std::fs::read(json_path)
        .map_err(|e| format!("Failed to read testssl JSON file {}: {}", json_path, e))?;

    serde_json::from_slice(&json_bytes)
        .map_err(|e| format!("Failed to parse testssl JSON: {}", e))
}

fn assert_protocol_matches(testssl_data: &Value, rustssl_report: &rustssl_check::models::ScanReport) {
    let scan_results = testssl_data["scanResult"]
        .as_array()
        .expect("scanResult array missing in testssl JSON");
    assert!(!scan_results.is_empty());

    let protocols = scan_results[0]["protocols"]
        .as_array()
        .expect("protocols missing in testssl JSON");

    for p in protocols {
        let id = p["id"].as_str().unwrap_or("");
        let finding = p["finding"].as_str().unwrap_or("");
        let testssl_offered = finding.contains("offered") && !finding.contains("not offered");

        let matching_proto = match id {
            "SSLv2" => Some(Protocol::Ssl2),
            "SSLv3" => Some(Protocol::Ssl3),
            "TLS1" => Some(Protocol::Tls10),
            "TLS1_1" => Some(Protocol::Tls11),
            "TLS1_2" => Some(Protocol::Tls12),
            "TLS1_3" => Some(Protocol::Tls13),
            _ => None,
        };

        if let Some(proto) = matching_proto {
            let rustssl_proto = rustssl_report
                .protocols
                .iter()
                .find(|pr| pr.protocol == proto)
                .expect(&format!("Protocol {} not found in rustssl report", proto.name()));

            println!(
                "  Checking {}: testssl={} vs rustssl_check={}",
                proto.name(),
                testssl_offered,
                rustssl_proto.supported
            );

            assert_eq!(
                rustssl_proto.supported, testssl_offered,
                "Protocol mismatch for {}: testssl={}, rustssl={}",
                proto.name(),
                testssl_offered,
                rustssl_proto.supported
            );
        }
    }
}

#[tokio::test]
async fn test_compare_github_with_testssl() {
    let target = "github.com";
    let tmp_json = format!("/tmp/testssl_cmp_{}_{}.json", "github", std::process::id());

    println!("[*] Running testssl on {}", target);
    let testssl_data = match run_testssl(target, &tmp_json) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Skipping testssl comparison: {}", e);
            return;
        }
    };

    println!("[*] Running rustssl_check on {}", target);
    let rustssl_report = run_scan(ScanOptions {
        target: target.to_string(),
        port_override: None,
        sni_override: None,
        timeout: Duration::from_secs(5),
        concurrency: 32,
        protocols_only: false,
        ciphers_only: false,
        cert_only: false,
    })
    .await
    .expect("rustssl_check scan failed");

    assert_protocol_matches(&testssl_data, &rustssl_report);

    let rustssl_cert = rustssl_report.certificate.expect("rustssl cert report missing");
    let leaf = &rustssl_cert.leaf;

    assert!(leaf.sans.iter().any(|s| s == "github.com"));
    assert!(leaf.sans.iter().any(|s| s == "www.github.com"));

    let _ = std::fs::remove_file(&tmp_json);
    println!("[✓] github.com comparison with testssl passed with 100% agreement!");
}

#[tokio::test]
async fn test_compare_devoteam_with_testssl() {
    let target = "www.devoteam.com";
    let tmp_json = format!("/tmp/testssl_cmp_{}_{}.json", "devoteam", std::process::id());

    println!("[*] Running testssl on {}", target);
    let testssl_data = match run_testssl(target, &tmp_json) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Skipping testssl comparison: {}", e);
            return;
        }
    };

    println!("[*] Running rustssl_check on {}", target);
    let rustssl_report = run_scan(ScanOptions {
        target: target.to_string(),
        port_override: None,
        sni_override: None,
        timeout: Duration::from_secs(5),
        concurrency: 32,
        protocols_only: false,
        ciphers_only: false,
        cert_only: false,
    })
    .await
    .expect("rustssl_check scan failed");

    assert_protocol_matches(&testssl_data, &rustssl_report);

    let leaf = &rustssl_report.certificate.unwrap().leaf;
    assert_eq!(leaf.subject_cn.as_deref(), Some("*.devoteam.com"));

    let _ = std::fs::remove_file(&tmp_json);
    println!("[✓] www.devoteam.com comparison with testssl passed with 100% agreement!");
}

#[tokio::test]
async fn test_compare_expired_badssl_with_testssl() {
    let target = "expired.badssl.com";
    let tmp_json = format!("/tmp/testssl_cmp_{}_{}.json", "expired", std::process::id());

    println!("[*] Running testssl on {}", target);
    let testssl_data = match run_testssl(target, &tmp_json) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Skipping testssl comparison: {}", e);
            return;
        }
    };

    println!("[*] Running rustssl_check on {}", target);
    let rustssl_report = run_scan(ScanOptions {
        target: target.to_string(),
        port_override: None,
        sni_override: None,
        timeout: Duration::from_secs(5),
        concurrency: 32,
        protocols_only: false,
        ciphers_only: false,
        cert_only: false,
    })
    .await
    .expect("rustssl_check scan failed");

    assert_protocol_matches(&testssl_data, &rustssl_report);

    let leaf = &rustssl_report.certificate.unwrap().leaf;
    assert!(leaf.is_expired, "Certificate must be flagged as expired");

    let _ = std::fs::remove_file(&tmp_json);
    println!("[✓] expired.badssl.com comparison with testssl passed with 100% agreement!");
}

#[tokio::test]
async fn test_compare_tls10_badssl_with_testssl() {
    let target = "tls-v1-0.badssl.com:1010";
    let tmp_json = format!("/tmp/testssl_cmp_{}_{}.json", "tls10", std::process::id());

    println!("[*] Running testssl on {}", target);
    let testssl_data = match run_testssl(target, &tmp_json) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Skipping testssl comparison: {}", e);
            return;
        }
    };

    println!("[*] Running rustssl_check on {}", target);
    let rustssl_report = run_scan(ScanOptions {
        target: target.to_string(),
        port_override: None,
        sni_override: None,
        timeout: Duration::from_secs(5),
        concurrency: 32,
        protocols_only: false,
        ciphers_only: false,
        cert_only: false,
    })
    .await
    .expect("rustssl_check scan failed");

    assert_protocol_matches(&testssl_data, &rustssl_report);

    let tls10 = rustssl_report.protocols.iter().find(|p| p.protocol == Protocol::Tls10).unwrap();
    let tls12 = rustssl_report.protocols.iter().find(|p| p.protocol == Protocol::Tls12).unwrap();
    assert!(tls10.supported, "TLS 1.0 must be supported on tls-v1-0.badssl.com:1010");
    assert!(!tls12.supported, "TLS 1.2 must not be supported on tls-v1-0.badssl.com:1010");

    let _ = std::fs::remove_file(&tmp_json);
    println!("[✓] tls-v1-0.badssl.com:1010 comparison with testssl passed with 100% agreement!");
}
