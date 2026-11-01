use crate::config::Settings;
use crate::core::{classify_ip, parse_ip, reverse_dns};
use crate::risk::calculate_risk;
use crate::sources::lookup_service;
use chrono::{SecondsFormat, Utc};
use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::thread;
use std::time::Duration;

pub const PROVIDERS: [&str; 4] = ["abuseipdb", "virustotal", "shodan", "greynoise"];

#[derive(Clone)]
pub struct AnalysisOptions {
    pub use_keyless: bool,
    pub providers: BTreeSet<String>,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            use_keyless: true,
            providers: PROVIDERS.iter().map(|name| (*name).to_owned()).collect(),
        }
    }
}

pub fn analyze(
    value: &str,
    settings: &Settings,
    options: &AnalysisOptions,
) -> Result<Value, String> {
    let address = parse_ip(value)?;
    let ip = address.to_string();
    let classification = classify_ip(address);
    let mut report = json!({
        "schema_version": "1.0",
        "generated_at": Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true),
        "target": ip,
        "classification": classification,
        "reverse_dns": reverse_dns(address),
        "rdap": {"status": "skipped"},
        "network": {"status": "skipped"},
        "geolocation": {"status": "skipped"},
        "providers": {},
        "warnings": [
            "Use only for lawful, authorized, passive intelligence gathering.",
            "IP geolocation is approximate and is not a physical device location."
        ],
    });
    let mut provider_results = BTreeMap::new();
    if !classification["is_global"].as_bool().unwrap_or(false) {
        report["warnings"].as_array_mut().unwrap().push(json!(
            "Network lookups were skipped because the address is not globally routable."
        ));
        report["risk"] = calculate_risk(&provider_results);
        return Ok(report);
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(Policy::limited(5))
        .user_agent("Barracuda-IP-Intelligence/0.2")
        .build()
        .map_err(|_| "HTTP istemcisi başlatılamadı".to_owned())?;
    // API keys must never be forwarded to another host through a redirect.
    let keyed_client = Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(Policy::none())
        .user_agent("Barracuda-IP-Intelligence/0.2")
        .build()
        .map_err(|_| "HTTP istemcisi başlatılamadı".to_owned())?;
    let mut jobs: Vec<(String, String)> = Vec::new();
    if options.use_keyless {
        for name in ["rdap", "network", "geolocation"] {
            jobs.push((name.to_owned(), String::new()));
        }
    }
    for name in PROVIDERS {
        if !options.providers.contains(name) {
            continue;
        }
        let key = settings.key_for(name);
        if key.is_empty() {
            let disabled = json!({"status": "not_configured", "provider": name});
            report["providers"][name] = disabled.clone();
            provider_results.insert(name.to_owned(), disabled);
        } else {
            jobs.push((name.to_owned(), key.to_owned()));
        }
    }

    let handles: Vec<_> = jobs
        .into_iter()
        .map(|(name, key)| {
            let client = if key.is_empty() {
                client.clone()
            } else {
                keyed_client.clone()
            };
            let ip = ip.clone();
            thread::spawn(move || {
                let result = lookup_service(&client, &name, &ip, &key).unwrap_or_else(
                    |error| json!({"status": "error", "source": name, "error": error}),
                );
                (name, result)
            })
        })
        .collect();
    for handle in handles {
        let (name, result) = handle
            .join()
            .map_err(|_| "Analiz iş parçacığı beklenmedik şekilde durdu".to_owned())?;
        if PROVIDERS.contains(&name.as_str()) {
            report["providers"][name.as_str()] = result.clone();
            provider_results.insert(name, result);
        } else {
            report[name.as_str()] = result;
        }
    }
    report["risk"] = calculate_risk(&provider_results);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::{AnalysisOptions, analyze};
    use crate::config::Settings;

    #[test]
    fn private_address_skips_remote_sources() {
        let report = analyze(
            "192.168.1.10",
            &Settings::default(),
            &AnalysisOptions::default(),
        )
        .unwrap();
        assert_eq!(report["classification"]["is_bogon"], true);
        assert_eq!(report["rdap"]["status"], "skipped");
        assert_eq!(report["risk"]["provider_count"], 0);
    }
}
