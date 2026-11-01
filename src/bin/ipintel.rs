use barracuda_ip_intelligence::config::Settings;
use barracuda_ip_intelligence::engine::{AnalysisOptions, PROVIDERS, analyze};
use barracuda_ip_intelligence::reporting::{write_csv, write_json};
use std::collections::BTreeSet;
use std::env;
use std::path::Path;

const HELP: &str = "Usage: ipintel <IP> [--no-keyless] [--providers all|name,...] [--json FILE] [--csv FILE] [--print-json]";

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let mut ip = None;
    let mut options = AnalysisOptions::default();
    let mut json_path = None;
    let mut csv_path = None;
    let mut print_json = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                println!("{HELP}");
                return Ok(());
            }
            "--no-keyless" => options.use_keyless = false,
            "--print-json" => print_json = true,
            "--json" => json_path = Some(args.next().ok_or("--json requires a file")?),
            "--csv" => csv_path = Some(args.next().ok_or("--csv requires a file")?),
            "--providers" => {
                let value = args.next().ok_or("--providers requires a value")?;
                options.providers = if value.eq_ignore_ascii_case("all") {
                    PROVIDERS.iter().map(|name| (*name).to_owned()).collect()
                } else {
                    value
                        .split(',')
                        .map(|name| name.trim().to_lowercase())
                        .filter(|name| !name.is_empty())
                        .collect::<BTreeSet<_>>()
                };
                for name in &options.providers {
                    if !PROVIDERS.contains(&name.as_str()) {
                        return Err(format!("Unknown provider: {name}"));
                    }
                }
            }
            _ if arg.starts_with('-') => return Err(format!("Unknown option: {arg}")),
            _ if ip.is_none() => ip = Some(arg),
            _ => return Err("Only one IP address is supported".to_owned()),
        }
    }
    let ip = ip.ok_or_else(|| HELP.to_owned())?;
    let report = analyze(&ip, &Settings::load(), &options)?;
    if let Some(path) = json_path {
        write_json(&report, Path::new(&path))?;
    }
    if let Some(path) = csv_path {
        write_csv(&report, Path::new(&path))?;
    }
    if print_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        let risk = &report["risk"];
        let label = if risk["provider_count"] == 0 {
            "UNKNOWN".to_owned()
        } else {
            risk["level"].as_str().unwrap_or("unknown").to_uppercase()
        };
        println!(
            "Target:      {} ({})",
            report["target"].as_str().unwrap_or(""),
            report["classification"]["type"].as_str().unwrap_or("")
        );
        println!("Global:      {}", report["classification"]["is_global"]);
        println!(
            "PTR:         {}",
            report["reverse_dns"]["hostname"].as_str().unwrap_or("-")
        );
        println!("ASN:         {}", report["network"]["asn"]);
        println!(
            "Prefix:      {}",
            report["network"]["prefix"].as_str().unwrap_or("-")
        );
        println!(
            "Country:     {}",
            report["geolocation"]["country"]
                .as_str()
                .or_else(|| report["rdap"]["country"].as_str())
                .unwrap_or("-")
        );
        println!("Risk:        {}/100 ({label})", risk["score"]);
        println!(
            "Confidence:  {}",
            risk["confidence"].as_str().unwrap_or("none")
        );
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Error: {error}");
        std::process::exit(2);
    }
}
