use net_autopsy::{AutopsyEngine, ReportFormatter};
use std::env;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    let mut domain = "api.openai.com".to_string();
    let mut port = 443u16;
    let mut json_output = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => {
                json_output = true;
            }
            "-p" | "--port" => {
                if i + 1 < args.len() {
                    if let Ok(p) = args[i + 1].parse::<u16>() {
                        port = p;
                        i += 1;
                    }
                }
            }
            "-h" | "--help" => {
                print_help();
                return;
            }
            d if !d.starts_with('-') => {
                domain = d
                    .trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .trim_end_matches('/')
                    .to_string();
            }
            _ => {}
        }
        i += 1;
    }

    if !json_output {
        println!("⚡ net-autopsy: Commencing Layer 3-7 forensic probe on '{domain}:{port}'...");
    }

    let report = AutopsyEngine::run_autopsy(&domain, port).await;

    if json_output {
        println!("{}", ReportFormatter::format_json(&report));
    } else {
        println!("{}", ReportFormatter::format_terminal(&report));
    }
}

fn print_help() {
    println!("net-autopsy — High-Precision Network Forensics & Censorship Autopsy Engine (OSI Layers 3-7)");
    println!("\nUSAGE:");
    println!("    net-autopsy <DOMAIN> [OPTIONS]");
    println!("\nOPTIONS:");
    println!("    -p, --port <PORT>    Target port to probe (default: 443)");
    println!("    --json               Output machine-readable JSON forensic report");
    println!("    -h, --help           Display this help message");
    println!("\nEXAMPLES:");
    println!("    net-autopsy api.openai.com");
    println!("    net-autopsy cursor.sh --json");
    println!("    net-autopsy discord.com -p 443");
}
