use serde_json::{Value, json};
use std::collections::BTreeMap;

fn weight(name: &str) -> f64 {
    match name {
        "abuseipdb" | "virustotal" => 0.35,
        "shodan" | "greynoise" => 0.15,
        _ => 0.1,
    }
}

pub fn calculate_risk(results: &BTreeMap<String, Value>) -> Value {
    let mut weighted_sum = 0.0;
    let mut active_weight = 0.0;
    let mut evidence = Vec::new();
    for (name, result) in results {
        if result["status"] != "ok" {
            continue;
        }
        let Some(raw) = result["score"].as_f64() else {
            continue;
        };
        let score = raw.clamp(0.0, 100.0);
        let w = weight(name);
        weighted_sum += score * w;
        active_weight += w;
        evidence.push(json!({"provider": name, "score": score.round() as u32, "weight": w}));
    }
    let final_score = if active_weight > 0.0 {
        (weighted_sum / active_weight).round() as u32
    } else {
        0
    };
    let level = match final_score {
        75..=100 => "critical",
        50..=74 => "high",
        25..=49 => "medium",
        _ => "low",
    };
    let confidence = match evidence.len() {
        0 => "none",
        1 => "limited",
        _ => "corroborated",
    };
    let notice = if evidence.is_empty() {
        "A low score with no provider evidence means unknown, not verified clean."
    } else {
        "Risk is a weighted indicator and must be reviewed with the source evidence."
    };
    json!({
        "score": final_score,
        "level": level,
        "evidence": evidence,
        "provider_count": evidence.len(),
        "confidence": confidence,
        "notice": notice,
    })
}

#[cfg(test)]
mod tests {
    use super::calculate_risk;
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn no_evidence_is_unknown() {
        let risk = calculate_risk(&BTreeMap::new());
        assert_eq!(risk["provider_count"], 0);
        assert_eq!(risk["confidence"], "none");
    }

    #[test]
    fn weighted_score_uses_successful_providers_only() {
        let results = BTreeMap::from([
            ("abuseipdb".to_owned(), json!({"status":"ok","score":100})),
            ("shodan".to_owned(), json!({"status":"error","score":100})),
            ("virustotal".to_owned(), json!({"status":"ok","score":0})),
        ]);
        let risk = calculate_risk(&results);
        assert_eq!(risk["score"], 50);
        assert_eq!(risk["provider_count"], 2);
    }
}
