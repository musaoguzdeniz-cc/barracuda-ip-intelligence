use reqwest::blocking::Client;
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;

fn get_json(
    client: &Client,
    url: &str,
    params: &[(&str, &str)],
    headers: &[(&str, &str)],
) -> Result<Value, String> {
    let mut request = client
        .get(url)
        .query(params)
        .header("Accept", "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    // Avoid returning reqwest error strings: Shodan puts the API key in the URL.
    let response = request
        .send()
        .map_err(|_| "Ağ isteği başarısız".to_owned())?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status().as_u16()));
    }
    let result = response
        .json::<Value>()
        .map_err(|_| "Kaynak geçerli JSON döndürmedi".to_owned())?;
    if !result.is_object() {
        return Err("Kaynak beklenmeyen veri döndürdü".to_owned());
    }
    Ok(result)
}

pub fn lookup_service(client: &Client, name: &str, ip: &str, key: &str) -> Result<Value, String> {
    match name {
        "rdap" => fetch_rdap(client, ip),
        "network" => fetch_network(client, ip),
        "geolocation" => fetch_geolocation(client, ip),
        "abuseipdb" => fetch_abuseipdb(client, ip, key),
        "virustotal" => fetch_virustotal(client, ip, key),
        "shodan" => fetch_shodan(client, ip, key),
        "greynoise" => fetch_greynoise(client, ip, key),
        _ => Err("Bilinmeyen kaynak".to_owned()),
    }
}

fn fetch_rdap(client: &Client, ip: &str) -> Result<Value, String> {
    let data = get_json(client, &format!("https://rdap.org/ip/{ip}"), &[], &[])?;
    let mut events = Map::new();
    for event in data["events"].as_array().into_iter().flatten() {
        if let (Some(action), Some(date)) = (event["eventAction"].as_str(), event.get("eventDate"))
        {
            events.insert(action.to_owned(), date.clone());
        }
    }
    let contacts: Vec<Value> = data["entities"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|entity| {
            let mut contact = json!({
                "handle": entity.get("handle"),
                "roles": entity.get("roles").cloned().unwrap_or_else(|| json!([])),
            });
            if let Some(items) = entity["vcardArray"].get(1).and_then(Value::as_array) {
                for item in items {
                    let Some(parts) = item.as_array() else {
                        continue;
                    };
                    if parts.len() >= 4 {
                        if let Some(name @ ("fn" | "email")) = parts[0].as_str() {
                            contact[name] = parts[3].clone();
                        }
                    }
                }
            }
            contact
        })
        .collect();
    Ok(json!({
        "status": "ok",
        "handle": data.get("handle"),
        "name": data.get("name"),
        "type": data.get("type"),
        "country": data.get("country"),
        "start_address": data.get("startAddress"),
        "end_address": data.get("endAddress"),
        "ip_version": data.get("ipVersion"),
        "port43": data.get("port43"),
        "events": events,
        "contacts": contacts,
        "source": "rdap.org bootstrap service",
    }))
}

fn fetch_network(client: &Client, ip: &str) -> Result<Value, String> {
    let response = get_json(
        client,
        "https://stat.ripe.net/data/prefix-overview/data.json",
        &[("resource", ip)],
        &[],
    )?;
    let data = &response["data"];
    let asns = data["asns"].as_array().cloned().unwrap_or_default();
    let first = asns.first().cloned().unwrap_or(Value::Null);
    let (asn, holder, numbers) = if first.is_object() {
        (
            first["asn"].clone(),
            first["holder"].clone(),
            asns.iter()
                .filter_map(|item| item.get("asn").cloned())
                .collect::<Vec<_>>(),
        )
    } else {
        (first, data["holder"].clone(), asns)
    };
    let block = &data["block"];
    let rir = block["desc"]
        .as_str()
        .and_then(|text| text.strip_prefix("Administered by "))
        .filter(|text| !text.is_empty());
    Ok(json!({
        "status": "ok",
        "asn": asn,
        "asns": numbers,
        "prefix": data.get("resource").or_else(|| data.get("prefix")),
        "holder": holder,
        "rir": rir,
        "allocation_block": block.get("resource"),
        "announced": data.get("announced"),
        "source": "RIPEstat",
    }))
}

fn fetch_geolocation(client: &Client, ip: &str) -> Result<Value, String> {
    let data = get_json(client, &format!("https://ipwho.is/{ip}"), &[], &[])?;
    if data["success"] == false {
        return Err(data["message"]
            .as_str()
            .unwrap_or("Geolocation lookup failed")
            .to_owned());
    }
    Ok(json!({
        "status": "ok",
        "country": data.get("country"),
        "country_code": data.get("country_code"),
        "region": data.get("region"),
        "city": data.get("city"),
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
        "timezone": data["timezone"].get("id"),
        "asn": data["connection"].get("asn"),
        "isp": data["connection"].get("isp"),
        "domain": data["connection"].get("domain"),
        "proxy": data["security"].get("proxy"),
        "vpn": data["security"].get("vpn"),
        "tor": data["security"].get("tor"),
        "hosting": data["security"].get("hosting"),
        "source": "ipwho.is",
        "accuracy_notice": "IP geolocation is approximate and is not a physical device location.",
    }))
}

fn fetch_abuseipdb(client: &Client, ip: &str, key: &str) -> Result<Value, String> {
    let response = get_json(
        client,
        "https://api.abuseipdb.com/api/v2/check",
        &[("ipAddress", ip), ("maxAgeInDays", "90"), ("verbose", "")],
        &[("Key", key)],
    )?;
    let data = &response["data"];
    let score = data["abuseConfidenceScore"]
        .as_i64()
        .unwrap_or(0)
        .clamp(0, 100);
    Ok(json!({
        "status": "ok",
        "provider": "abuseipdb",
        "score": score,
        "abuse_confidence_score": score,
        "total_reports": data.get("totalReports"),
        "last_reported_at": data.get("lastReportedAt"),
        "usage_type": data.get("usageType"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "country_code": data.get("countryCode"),
        "is_tor": data.get("isTor"),
    }))
}

fn fetch_virustotal(client: &Client, ip: &str, key: &str) -> Result<Value, String> {
    let response = get_json(
        client,
        &format!("https://www.virustotal.com/api/v3/ip_addresses/{ip}"),
        &[],
        &[("x-apikey", key)],
    )?;
    let attributes = &response["data"]["attributes"];
    let stats = &attributes["last_analysis_stats"];
    let count = |name: &str| stats[name].as_u64().unwrap_or(0);
    let malicious = count("malicious");
    let suspicious = count("suspicious");
    let total = malicious + suspicious + count("harmless") + count("undetected");
    let score = if total == 0 {
        0
    } else {
        (100.0 * (malicious as f64 + suspicious as f64 * 0.5) / total as f64).round() as u64
    };
    Ok(json!({
        "status": "ok",
        "provider": "virustotal",
        "score": score.min(100),
        "analysis_stats": stats,
        "reputation": attributes.get("reputation"),
        "network": attributes.get("network"),
        "as_owner": attributes.get("as_owner"),
        "country": attributes.get("country"),
        "tags": attributes.get("tags").cloned().unwrap_or_else(|| json!([])),
    }))
}

fn fetch_shodan(client: &Client, ip: &str, key: &str) -> Result<Value, String> {
    let data = get_json(
        client,
        &format!("https://api.shodan.io/shodan/host/{ip}"),
        &[("key", key)],
        &[],
    )?;
    let vulns = &data["vulns"];
    let vuln_count = vulns
        .as_array()
        .map(Vec::len)
        .or_else(|| vulns.as_object().map(Map::len))
        .unwrap_or(0);
    let tags = data["tags"].as_array().cloned().unwrap_or_default();
    let suspicious = ["malware", "botnet", "compromised", "scanner", "tor"];
    let matched: BTreeSet<String> = tags
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_lowercase)
        .filter(|tag| suspicious.contains(&tag.as_str()))
        .collect();
    let score = (vuln_count * 12 + matched.len() * 20).min(100);
    Ok(json!({
        "status": "ok",
        "provider": "shodan",
        "score": score,
        "organization": data.get("org"),
        "isp": data.get("isp"),
        "asn": data.get("asn"),
        "ports": data.get("ports").cloned().unwrap_or_else(|| json!([])),
        "hostnames": data.get("hostnames").cloned().unwrap_or_else(|| json!([])),
        "tags": tags,
        "vulnerabilities": vulns,
        "last_update": data.get("last_update"),
    }))
}

fn fetch_greynoise(client: &Client, ip: &str, key: &str) -> Result<Value, String> {
    let data = get_json(
        client,
        &format!("https://api.greynoise.io/v3/community/{ip}"),
        &[],
        &[("key", key)],
    )?;
    let classification = data["classification"]
        .as_str()
        .unwrap_or("unknown")
        .to_lowercase();
    let score = match classification.as_str() {
        "malicious" => 100,
        "suspicious" => 60,
        "benign" => 0,
        _ if data["noise"] == true => 10,
        _ => 0,
    };
    Ok(json!({
        "status": "ok",
        "provider": "greynoise",
        "score": score,
        "classification": classification,
        "noise": data.get("noise"),
        "riot": data.get("riot"),
        "name": data.get("name"),
        "link": data.get("link"),
        "last_seen": data.get("last_seen"),
        "message": data.get("message"),
    }))
}

#[cfg(test)]
mod tests {
    use super::lookup_service;
    use reqwest::blocking::Client;

    #[test]
    fn unknown_source_fails_without_network() {
        assert!(lookup_service(&Client::new(), "unknown", "8.8.8.8", "").is_err());
    }
}
