use crate::models::{
    CertificateChainReport, CipherSuiteInfo, ProtocolCipherGroup, ProtocolResult, ScanReport,
    SecurityRating, VulnerabilityFinding,
};
use colored::*;

pub fn print_report(report: &ScanReport, hide_rejected: bool) {
    print_banner();
    print_target_info(report);
    print_protocol_section(&report.protocols);
    if let Some(ref cert) = report.certificate {
        print_certificate_section(cert);
    }
    print_cipher_section_by_protocol(
        &report.protocol_ciphers,
        &report.supported_ciphers,
        report.rejected_ciphers_count,
        report.server_cipher_preference.as_deref(),
        hide_rejected,
    );
    print_findings_section(&report.findings);
    print_summary(report);
}

fn print_banner() {
    println!();
    println!(
        "{} {}",
        "rustssl_check".bold(),
        "— TLS/SSL Protocol, Cipher & Cert Auditor".dimmed()
    );
    println!();
}

fn print_section_header(title: &str) {
    let line_len = 72usize.saturating_sub(title.len() + 4);
    println!(
        "── {} {}",
        title.bold(),
        "─".repeat(line_len).dimmed()
    );
}

fn print_target_info(report: &ScanReport) {
    print_section_header("Target Information");
    println!("  {:<18}: {}", "Target Host", report.target_host.bold());
    println!("  {:<18}: {}", "Port", report.target_port);
    println!("  {:<18}: {}", "Resolved IP", report.target_ip);
    println!("  {:<18}: {} ms", "Connection RTT", report.rtt_ms);
    println!("  {:<18}: {} ms", "Scan Duration", report.scan_duration_ms);
    println!();
}

fn format_rating(rating: SecurityRating) -> ColoredString {
    match rating {
        SecurityRating::Recommended => "Recommended".green(),
        SecurityRating::Secure => "Secure".green(),
        SecurityRating::Deprecated => "Deprecated".yellow(),
        SecurityRating::Weak => "Weak".yellow(),
        SecurityRating::Insecure => "Insecure".red(),
        SecurityRating::Critical => "Critical".red().bold(),
    }
}

fn print_protocol_section(protocols: &[ProtocolResult]) {
    print_section_header("Protocol Support & Obsolescence");
    println!(
        "  {:<12} {:<18} {}",
        "Protocol".bold(),
        "Status".bold(),
        "Rating".bold()
    );
    println!("  {}", "─".repeat(45).dimmed());

    for p in protocols {
        let status_str = if p.supported {
            if p.protocol.is_obsolete() {
                format!("{:<18}", "Offered (Obsolete)").red()
            } else {
                format!("{:<18}", "Offered").green()
            }
        } else {
            format!("{:<18}", "Not Offered").dimmed()
        };

        let rating_str = if p.supported {
            format_rating(p.rating)
        } else {
            "-".dimmed()
        };

        println!(
            "  {:<12} {} {}",
            p.protocol.name(),
            status_str,
            rating_str
        );
    }
    println!();
}

fn print_certificate_section(cert: &CertificateChainReport) {
    let leaf = &cert.leaf;
    print_section_header("Certificate Information");

    // Subject
    let sub_cn = leaf.subject_cn.as_deref().unwrap_or("N/A");
    let sub_o = leaf.subject_o.as_deref().unwrap_or("N/A");
    println!("  {:<20}: {}", "Common Name (CN)", sub_cn);
    if sub_o != "N/A" {
        println!("  {:<20}: {}", "Organization (O)", sub_o);
    }

    // Issuer
    let iss_cn = leaf.issuer_cn.as_deref().unwrap_or("N/A");
    let iss_o = leaf.issuer_o.as_deref().unwrap_or("N/A");
    println!("  {:<20}: {}", "Issuer CN", iss_cn);
    if iss_o != "N/A" {
        println!("  {:<20}: {}", "Issuer Org", iss_o);
    }

    // Validity
    let validity_status = if leaf.is_expired {
        format!("Expired ({} days ago)", leaf.days_remaining.abs()).red().bold()
    } else if leaf.days_remaining <= 14 {
        format!("Expiring soon ({} days left)", leaf.days_remaining).yellow().bold()
    } else {
        format!("Valid ({} days remaining)", leaf.days_remaining).green()
    };

    println!("  {:<20}: {}", "Validity Status", validity_status);
    println!("  {:<20}: {}", "Not Before", leaf.not_before.dimmed());
    println!("  {:<20}: {}", "Not After", leaf.not_after.dimmed());

    // SANs
    if !leaf.sans.is_empty() {
        let san_preview = if leaf.sans.len() <= 5 {
            leaf.sans.join(", ")
        } else {
            format!("{} (and {} more...)", leaf.sans[..5].join(", "), leaf.sans.len() - 5)
        };
        println!("  {:<20}: {}", "SANs", san_preview);
    }

    // Key & Signature
    println!(
        "  {:<20}: {} ({})",
        "Public Key",
        leaf.public_key_type,
        format_rating(leaf.key_rating)
    );
    println!(
        "  {:<20}: {} ({})",
        "Signature Alg",
        leaf.signature_algorithm,
        format_rating(leaf.sig_alg_rating)
    );

    // Trust Chain
    if let Some(valid) = cert.trust_valid {
        if valid {
            println!(
                "  {:<20}: {}",
                "Mozilla Trust Chain",
                "Verified (Trusted Root CA)".green()
            );
        } else {
            let err = cert.trust_error.as_deref().unwrap_or("Untrusted / Self-signed");
            println!(
                "  {:<20}: {} ({})",
                "Mozilla Trust Chain",
                "Unverified / Untrusted".red(),
                err.dimmed()
            );
        }
    }

    // Fingerprints
    println!("  {:<20}: {}", "SHA-256 Fingerprint", leaf.sha256_fingerprint.dimmed());
    println!("  {:<20}: {}", "Serial Number", leaf.serial_number.dimmed());

    // Intermediates
    if !cert.intermediates.is_empty() {
        println!("  {:<20}: {} certificate(s)", "Chain Length", cert.intermediates.len() + 1);
        for (i, inter) in cert.intermediates.iter().enumerate() {
            println!(
                "    Intermediate #{}: CN={}, Org={}",
                i + 1,
                inter.subject_cn.as_deref().unwrap_or("Unknown"),
                inter.subject_o.as_deref().unwrap_or("Unknown").dimmed()
            );
        }
    }
    println!();
}

fn print_cipher_section_by_protocol(
    groups: &[ProtocolCipherGroup],
    all_supported: &[CipherSuiteInfo],
    rejected_count: usize,
    preference: Option<&str>,
    hide_rejected: bool,
) {
    print_section_header("Supported Cipher Suites by Protocol");
    if let Some(pref) = preference {
        println!("  {:<18}: {}", "Cipher Ordering", pref);
    }
    let summary_str = if hide_rejected {
        format!(
            "{} unique supported across {} active protocol(s)",
            all_supported.len(),
            groups.len(),
        )
    } else {
        format!(
            "{} unique supported across {} active protocol(s) ({} rejected)",
            all_supported.len(),
            groups.len(),
            rejected_count,
        )
    };
    println!("  {:<18}: {}", "Summary", summary_str);
    println!();

    if groups.is_empty() {
        println!("  {}", "No supported ciphers detected from scan suite.".dimmed());
        println!();
        return;
    }

    for group in groups {
        let proto_header = if group.protocol.is_obsolete() {
            format!("[ {} ] ({} cipher(s) supported)", group.protocol.name(), group.ciphers.len()).red()
        } else {
            format!("[ {} ] ({} cipher(s) supported)", group.protocol.name(), group.ciphers.len()).bold()
        };

        println!("  {}", proto_header);
        println!(
            "    {:<8} {:<45} {:<14} {:<8} {}",
            "ID".bold(),
            "IANA Cipher Name".bold(),
            "KeyEx".bold(),
            "Bits".bold(),
            "Rating".bold()
        );
        println!("    {}", "─".repeat(88).dimmed());

        for c in &group.ciphers {
            let id_str = format!("{:<8}", format!("0x{:04x}", c.id)).dimmed();
            let name_str = format!("{:<45}", c.iana_name);

            let kx_plain = if c.forward_secrecy {
                format!("{}+FS", c.key_exchange)
            } else {
                c.key_exchange.to_string()
            };
            let kx_str = if c.forward_secrecy {
                format!("{:<14}", kx_plain).green()
            } else {
                format!("{:<14}", kx_plain).dimmed()
            };

            let bits_str = format!("{:<8}", format!("{}b", c.key_bits)).dimmed();
            let rating_str = format_rating(c.rating);

            println!(
                "    {} {} {} {} {}",
                id_str,
                name_str,
                kx_str,
                bits_str,
                rating_str
            );
        }
        println!();
    }
}

fn print_findings_section(findings: &[VulnerabilityFinding]) {
    print_section_header("Security Findings & Vulnerabilities");

    if findings.is_empty() {
        println!(
            "  {} {}",
            "✓".green(),
            "No obsolete protocols, weak ciphers, or certificate defects detected.".green()
        );
        println!();
        return;
    }

    for f in findings {
        let (badge, title_color) = match f.rating {
            SecurityRating::Critical => ("[Critical]".red().bold(), f.title.red().bold()),
            SecurityRating::Insecure => ("[Insecure]".red(), f.title.red()),
            SecurityRating::Deprecated => ("[Deprecated]".yellow(), f.title.yellow()),
            SecurityRating::Weak => ("[Weak]".yellow(), f.title.yellow()),
            _ => ("[Info]".cyan(), f.title.cyan()),
        };

        println!("  {} {}", badge, title_color);
        println!("    {}", f.description);
        println!();
    }
}

fn print_summary(report: &ScanReport) {
    print_section_header("Overall Security Posture");
    let (grade_label, grade_color, desc_str) = match report.overall_rating {
        SecurityRating::Recommended => (
            "Grade: A+ (Recommended)",
            colored::Color::Green,
            "Modern TLS 1.3/1.2 only, robust AEAD ciphers with Forward Secrecy, valid certificate.",
        ),
        SecurityRating::Secure => (
            "Grade: A (Secure)",
            colored::Color::Green,
            "Secure configuration, no critical or obsolete protocols/ciphers.",
        ),
        SecurityRating::Deprecated => (
            "Grade: B (Deprecated protocols/ciphers)",
            colored::Color::Yellow,
            "Server enables deprecated protocols (TLS 1.0/1.1) or legacy cipher suites.",
        ),
        SecurityRating::Weak => (
            "Grade: C (Weak ciphers/cert)",
            colored::Color::Yellow,
            "Configuration contains weak ciphers (CBC mode, static RSA, or key size issues).",
        ),
        SecurityRating::Insecure => (
            "Grade: F (Insecure configuration)",
            colored::Color::Red,
            "Vulnerable to known attacks (3DES Sweet32, RC4, or untrusted/expired certificate).",
        ),
        SecurityRating::Critical => (
            "Grade: F-Critical (Immediate action required)",
            colored::Color::Red,
            "Critical vulnerabilities present (SSLv2, SSLv3 POODLE, NULL cleartext, or FREAK export ciphers).",
        ),
    };

    println!("  {}", grade_label.color(grade_color).bold());
    println!("  {}", desc_str.dimmed());
    println!();
}
