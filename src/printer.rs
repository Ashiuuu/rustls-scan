use crate::models::{
    CertificateChainReport, CipherSuiteInfo, ProtocolCipherGroup, ProtocolResult, ScanReport,
    SecurityRating, VulnerabilityFinding,
};
use colored::*;

pub fn print_report(report: &ScanReport, _hide_rejected: bool) {
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
    );
    print_findings_section(&report.findings);
    print_summary(report);
}

fn print_banner() {
    println!();
    println!(
        "{}",
        "╔══════════════════════════════════════════════════════════════════════╗"
            .bright_cyan()
            .bold()
    );
    println!(
        "{}  {}  {}",
        "║".bright_cyan().bold(),
        "rustssl_check — Fast TLS/SSL Protocol, Cipher & Cert Auditor"
            .bright_white()
            .bold(),
        "║".bright_cyan().bold()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════════════════════════╝"
            .bright_cyan()
            .bold()
    );
    println!();
}

fn print_target_info(report: &ScanReport) {
    println!("{}", "─── [ TARGET INFORMATION ] ────────────────────────────────────────────".bright_blue().bold());
    println!(
        "  {:<18}: {}",
        "Target Host".bold(),
        report.target_host.bright_white().bold()
    );
    println!(
        "  {:<18}: {}",
        "Port".bold(),
        report.target_port.to_string().cyan()
    );
    println!(
        "  {:<18}: {}",
        "Resolved IP".bold(),
        report.target_ip.cyan()
    );
    println!(
        "  {:<18}: {} ms",
        "Connection RTT".bold(),
        report.rtt_ms.to_string().yellow()
    );
    println!(
        "  {:<18}: {} ms",
        "Scan Duration".bold(),
        report.scan_duration_ms.to_string().yellow()
    );
    println!();
}

fn center_text(text: &str, width: usize) -> String {
    if text.len() >= width {
        return text.to_string();
    }
    let total_spaces = width - text.len();
    let left_spaces = total_spaces / 2;
    let right_spaces = total_spaces - left_spaces;
    format!("{}{}{}", " ".repeat(left_spaces), text, " ".repeat(right_spaces))
}

fn format_rating(rating: SecurityRating) -> ColoredString {
    let centered = center_text(rating.badge_text(), 15);
    match rating {
        SecurityRating::Recommended => centered.on_green().bold().white(),
        SecurityRating::Secure => centered.on_bright_green().bold().black(),
        SecurityRating::Deprecated => centered.on_yellow().bold().black(),
        SecurityRating::Weak => centered.on_bright_yellow().bold().black(),
        SecurityRating::Insecure => centered.on_red().bold().white(),
        SecurityRating::Critical => centered.on_bright_red().bold().white(),
    }
}

fn format_safe_badge() -> ColoredString {
    let centered = center_text("SAFE", 15);
    centered.on_bright_black().bold().white()
}

fn print_protocol_section(protocols: &[ProtocolResult]) {
    println!("{}", "─── [ PROTOCOL SUPPORT & OBSOLESCENCE ] ────────────────────────────────".bright_blue().bold());
    println!(
        "  {:<12} {:<22} {:<17} {}",
        "Protocol".bold(),
        "Status".bold(),
        "Rating".bold(),
        "Details / RFC Compliance".bold()
    );
    println!("  {}", "─".repeat(74).dimmed());

    for p in protocols {
        let (status_plain, is_obs) = if p.supported {
            if p.protocol.is_obsolete() {
                ("Offered (Obsolete)", true)
            } else {
                ("Offered (Active)", false)
            }
        } else {
            ("Not Offered", false)
        };

        let status_colored = if p.supported {
            if is_obs {
                format!("{:<22}", status_plain).bright_red().bold()
            } else {
                format!("{:<22}", status_plain).bright_green().bold()
            }
        } else {
            format!("{:<22}", status_plain).dimmed()
        };

        let rating_badge = if p.supported {
            format_rating(p.rating)
        } else {
            format_safe_badge()
        };

        println!(
            "  {:<12} {} {} {}",
            p.protocol.name().bold(),
            status_colored,
            rating_badge,
            p.notes.dimmed()
        );
    }
    println!();
}

fn print_certificate_section(cert: &CertificateChainReport) {
    let leaf = &cert.leaf;
    println!("{}", "─── [ CERTIFICATE INFORMATION ] ────────────────────────────────────────".bright_blue().bold());

    // Subject
    let sub_cn = leaf.subject_cn.as_deref().unwrap_or("N/A");
    let sub_o = leaf.subject_o.as_deref().unwrap_or("N/A");
    println!("  {:<20}: {}", "Common Name (CN)".bold(), sub_cn.bright_white().bold());
    if sub_o != "N/A" {
        println!("  {:<20}: {}", "Organization (O)".bold(), sub_o.white());
    }

    // Issuer
    let iss_cn = leaf.issuer_cn.as_deref().unwrap_or("N/A");
    let iss_o = leaf.issuer_o.as_deref().unwrap_or("N/A");
    println!("  {:<20}: {}", "Issuer CN".bold(), iss_cn.bright_cyan());
    if iss_o != "N/A" {
        println!("  {:<20}: {}", "Issuer Org".bold(), iss_o.cyan());
    }

    // Validity
    let validity_status = if leaf.is_expired {
        format!("EXPIRED ({} days ago)", leaf.days_remaining.abs()).bright_red().bold()
    } else if leaf.days_remaining <= 14 {
        format!("EXPIRING SOON ({} days left)", leaf.days_remaining).bright_yellow().bold()
    } else {
        format!("Valid ({} days remaining)", leaf.days_remaining).bright_green().bold()
    };

    println!("  {:<20}: {}", "Validity Status".bold(), validity_status);
    println!("  {:<20}: {}", "Not Before".bold(), leaf.not_before.dimmed());
    println!("  {:<20}: {}", "Not After".bold(), leaf.not_after.dimmed());

    // SANs
    if !leaf.sans.is_empty() {
        let san_preview = if leaf.sans.len() <= 5 {
            leaf.sans.join(", ")
        } else {
            format!("{} (and {} more...)", leaf.sans[..5].join(", "), leaf.sans.len() - 5)
        };
        println!("  {:<20}: {}", "SANs".bold(), san_preview.bright_blue());
    }

    // Key & Signature
    let key_rating_badge = format_rating(leaf.key_rating);
    let sig_rating_badge = format_rating(leaf.sig_alg_rating);
    println!(
        "  {:<20}: {} [{}]",
        "Public Key".bold(),
        leaf.public_key_type.bright_white(),
        key_rating_badge
    );
    println!(
        "  {:<20}: {} [{}]",
        "Signature Alg".bold(),
        leaf.signature_algorithm.bright_white(),
        sig_rating_badge
    );

    // Trust Chain
    if let Some(valid) = cert.trust_valid {
        if valid {
            println!(
                "  {:<20}: {}",
                "Mozilla Trust Chain".bold(),
                "VERIFIED (Trusted Root CA)".bright_green().bold()
            );
        } else {
            let err = cert.trust_error.as_deref().unwrap_or("Untrusted / Self-signed");
            println!(
                "  {:<20}: {} ({})",
                "Mozilla Trust Chain".bold(),
                "UNVERIFIED / UNTRUSTED".bright_red().bold(),
                err.red()
            );
        }
    }

    // Fingerprints
    println!("  {:<20}: {}", "SHA-256 Fingerprint".bold(), leaf.sha256_fingerprint.dimmed());
    println!("  {:<20}: {}", "Serial Number".bold(), leaf.serial_number.dimmed());

    // Intermediates
    if !cert.intermediates.is_empty() {
        println!("  {:<20}: {} certificate(s)", "Chain Length".bold(), cert.intermediates.len() + 1);
        for (i, inter) in cert.intermediates.iter().enumerate() {
            println!(
                "    Intermediate #{}: CN={}, Org={}",
                i + 1,
                inter.subject_cn.as_deref().unwrap_or("Unknown").bright_cyan(),
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
) {
    println!("{}", "─── [ SUPPORTED CIPHER SUITES BY PROTOCOL ] ────────────────────────────".bright_blue().bold());
    if let Some(pref) = preference {
        println!("  {:<20}: {}", "Cipher Ordering".bold(), pref.bright_cyan());
    }
    println!(
        "  {:<20}: {} unique supported across {} active protocol(s) ({} rejected)",
        "Summary".bold(),
        all_supported.len().to_string().bright_green().bold(),
        groups.len().to_string().cyan().bold(),
        rejected_count.to_string().dimmed()
    );
    println!();

    if groups.is_empty() {
        println!("  {}", "No supported ciphers detected from scan suite.".yellow());
        println!();
        return;
    }

    for group in groups {
        let proto_badge = if group.protocol.is_obsolete() {
            format!("[ {} ]", group.protocol.name()).bright_red().bold()
        } else {
            format!("[ {} ]", group.protocol.name()).bright_green().bold()
        };

        println!(
            "  ┌─ {} ── ({} cipher(s) supported) {}",
            proto_badge,
            group.ciphers.len().to_string().bold(),
            "─".repeat(50).dimmed()
        );
        println!(
            "  │ {:<8} {:<45} {:<14} {:<8} {:<17} {}",
            "ID".bold(),
            "IANA Cipher Name".bold(),
            "KeyEx".bold(),
            "Bits".bold(),
            "Rating".bold(),
            "Notes / Weaknesses".bold()
        );
        println!("  │ {}", "─".repeat(110).dimmed());

        for c in &group.ciphers {
            let id_str = format!("{:<8}", format!("0x{:04x}", c.id)).dimmed();
            let name_str = format!("{:<45}", c.iana_name).bright_white().bold();

            let kx_plain = if c.forward_secrecy {
                format!("{}+FS", c.key_exchange)
            } else {
                c.key_exchange.to_string()
            };
            let kx_str = if c.forward_secrecy {
                format!("{:<14}", kx_plain).green()
            } else {
                format!("{:<14}", kx_plain).yellow()
            };

            let bits_str = format!("{:<8}", format!("{}b", c.key_bits)).dimmed();
            let rating_badge = format_rating(c.rating);
            let note_str = c.vulnerability_note.unwrap_or("").bright_yellow();

            println!(
                "  │ {} {} {} {} {} {}",
                id_str,
                name_str,
                kx_str,
                bits_str,
                rating_badge,
                note_str
            );
        }
        println!("  └{}", "─".repeat(112).dimmed());
        println!();
    }
}

fn print_findings_section(findings: &[VulnerabilityFinding]) {
    println!("{}", "─── [ SECURITY FINDINGS & VULNERABILITIES ] ────────────────────────────".bright_blue().bold());

    if findings.is_empty() {
        println!(
            "  {} {}",
            "✓".bright_green().bold(),
            "No obsolete protocols, weak ciphers, or certificate defects detected! Server configuration meets modern security guidelines.".bright_green()
        );
        println!();
        return;
    }

    for f in findings {
        let (icon, badge) = match f.rating {
            SecurityRating::Critical => ("✗".bright_red().bold(), "CRITICAL".on_bright_red().bold().white()),
            SecurityRating::Insecure => ("✗".red().bold(), "INSECURE".on_red().bold().white()),
            SecurityRating::Deprecated => ("⚠".yellow().bold(), "DEPRECATED".on_yellow().bold().black()),
            SecurityRating::Weak => ("⚠".bright_yellow().bold(), "WEAK".on_bright_yellow().bold().black()),
            _ => ("ℹ".cyan().bold(), "INFO".on_cyan().bold().black()),
        };

        println!("  {} [{}] {}", icon, badge, f.title.bright_white().bold());
        println!("     {}: {}", "Description".bold(), f.description.white());
        println!("     {}: {}", "Remediation".bold(), f.remediation.bright_cyan());
        println!();
    }
}

fn print_summary(report: &ScanReport) {
    println!("{}", "─── [ OVERALL SECURITY POSTURE ] ───────────────────────────────────────".bright_blue().bold());
    let (grade_str, desc_str) = match report.overall_rating {
        SecurityRating::Recommended => (
            " GRADE: A+ (RECOMMENDED) ".on_green().bold().white(),
            "Modern TLS 1.3/1.2 only, robust AEAD ciphers with Forward Secrecy, valid certificate.",
        ),
        SecurityRating::Secure => (
            " GRADE: A (SECURE) ".on_bright_green().bold().black(),
            "Secure configuration, no critical or obsolete protocols/ciphers.",
        ),
        SecurityRating::Deprecated => (
            " GRADE: B (DEPRECATED PROTOCOLS/CIPHERS) ".on_yellow().bold().black(),
            "Server enables deprecated protocols (TLS 1.0/1.1) or legacy cipher suites.",
        ),
        SecurityRating::Weak => (
            " GRADE: C (WEAK CIPHERS/CERT) ".on_bright_yellow().bold().black(),
            "Configuration contains weak ciphers (CBC mode, static RSA, or key size issues).",
        ),
        SecurityRating::Insecure => (
            " GRADE: F (INSECURE CONFIGURATION) ".on_red().bold().white(),
            "Vulnerable to known attacks (3DES Sweet32, RC4, or untrusted/expired certificate).",
        ),
        SecurityRating::Critical => (
            " GRADE: F-CRITICAL (IMMEDIATE ACTION REQUIRED) ".on_bright_red().bold().white(),
            "Critical vulnerabilities present (SSLv2, SSLv3 POODLE, NULL cleartext, or FREAK export ciphers).",
        ),
    };

    println!("  {}", grade_str);
    println!("  {}", desc_str.bright_white());
    println!();
}
