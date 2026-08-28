use clap::Parser;
use rustssl_check::printer;
use rustssl_check::tls::scanner::{run_scan, ScanOptions};
use std::time::Duration;

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

    /// Output full report as structured JSON
    #[arg(long = "json")]
    json: bool,

    /// Test only SSL/TLS protocols
    #[arg(long = "protocols-only")]
    protocols_only: bool,

    /// Test only supported cipher suites
    #[arg(long = "ciphers-only")]
    ciphers_only: bool,

    /// Test and display only certificate information
    #[arg(long = "cert-only")]
    cert_only: bool,

    /// Hide rejected cipher counts
    #[arg(long = "hide-rejected")]
    hide_rejected: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let options = ScanOptions {
        target: cli.target.clone(),
        port_override: cli.port,
        sni_override: cli.sni,
        timeout: Duration::from_millis(cli.timeout_ms),
        concurrency: cli.concurrency,
        protocols_only: cli.protocols_only,
        ciphers_only: cli.ciphers_only,
        cert_only: cli.cert_only,
    };

    match run_scan(options).await {
        Ok(report) => {
            if cli.json {
                match serde_json::to_string_pretty(&report) {
                    Ok(json_str) => println!("{}", json_str),
                    Err(e) => {
                        eprintln!("Error serializing report to JSON: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                printer::print_report(&report, cli.hide_rejected);
            }
        }
        Err(err) => {
            eprintln!("\x1b[1;31mError:\x1b[0m {}", err);
            std::process::exit(1);
        }
    }
}
