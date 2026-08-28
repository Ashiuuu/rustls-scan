use clap::{Parser, ValueEnum};
use rustssl_check::printer;
use rustssl_check::tls::scanner::{run_scan, ScanOptions};
use std::time::Duration;

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ScanScope {
    #[default]
    All,
    Protocols,
    Ciphers,
    Cert,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

#[derive(Parser, Debug)]
#[command(
    name = "rustssl_check",
    author = "rustssl_check team",
    version = "0.1.0",
    about = "Fast, reduced, and robust TLS/SSL security auditor in Rust (testssl.sh reduced port)"
)]
struct Cli {
    /// Target host to scan (e.g. example.com, example.com:443, https://example.com)
    #[arg(required = true)]
    target: String,

    /// Port to connect to (overrides target port if provided)
    #[arg(short = 'p', long = "port")]
    port: Option<u16>,

    /// Custom SNI (Server Name Indication) hostname
    #[arg(long = "sni")]
    sni: Option<String>,

    /// Connection and probe timeout in milliseconds
    #[arg(short = 't', long = "timeout", default_value_t = 3000)]
    timeout_ms: u64,

    /// Maximum concurrent cipher probes
    #[arg(short = 'c', long = "concurrency", default_value_t = 32)]
    concurrency: usize,

    /// Probing scope: all, protocols, ciphers, cert
    #[arg(short = 's', long = "scan", value_enum, default_value_t = ScanScope::All)]
    scan: ScanScope,

    /// Output format: text, json
    #[arg(short = 'o', long = "output", value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,

    /// Shorthand for --output json
    #[arg(long = "json")]
    json: bool,

    /// Test only SSL/TLS protocols (legacy flag)
    #[arg(long = "protocols-only", hide = true)]
    protocols_only: bool,

    /// Test only supported cipher suites (legacy flag)
    #[arg(long = "ciphers-only", hide = true)]
    ciphers_only: bool,

    /// Test and display only certificate information (legacy flag)
    #[arg(long = "cert-only", hide = true)]
    cert_only: bool,

    /// Hide rejected cipher counts in summary
    #[arg(long = "hide-rejected")]
    hide_rejected: bool,

    /// Filter and output only items with security vulnerabilities/weaknesses
    #[arg(
        long = "vuln-only",
        alias = "vulnerable-only",
        alias = "vulnerable-ciphers-only",
        alias = "only-vulnerable-ciphers"
    )]
    vuln_only: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let protocols_only = cli.protocols_only || cli.scan == ScanScope::Protocols;
    let ciphers_only = cli.ciphers_only || cli.scan == ScanScope::Ciphers;
    let cert_only = cli.cert_only || cli.scan == ScanScope::Cert;
    let is_json = cli.json || cli.output == OutputFormat::Json;

    let options = ScanOptions {
        target: cli.target.clone(),
        port_override: cli.port,
        sni_override: cli.sni,
        timeout: Duration::from_millis(cli.timeout_ms),
        concurrency: cli.concurrency,
        protocols_only,
        ciphers_only,
        cert_only,
    };

    match run_scan(options).await {
        Ok(report) => {
            if is_json {
                if cli.vuln_only {
                    let vuln_report = report.to_vulnerable_report();
                    match serde_json::to_string_pretty(&vuln_report) {
                        Ok(json_str) => println!("{}", json_str),
                        Err(e) => {
                            eprintln!("Error serializing report to JSON: {}", e);
                            std::process::exit(1);
                        }
                    }
                } else {
                    match serde_json::to_string_pretty(&report) {
                        Ok(json_str) => println!("{}", json_str),
                        Err(e) => {
                            eprintln!("Error serializing report to JSON: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
            } else {
                printer::print_report(&report, cli.hide_rejected, cli.vuln_only);
            }
        }
        Err(err) => {
            eprintln!("\x1b[1;31mError:\x1b[0m {}", err);
            std::process::exit(1);
        }
    }
}
