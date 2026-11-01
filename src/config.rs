use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Default)]
pub struct Settings {
    pub abuseipdb_api_key: String,
    pub virustotal_api_key: String,
    pub shodan_api_key: String,
    pub greynoise_api_key: String,
}

impl Settings {
    pub fn load() -> Self {
        let env_file = local_env_file();
        let values = env_file
            .as_deref()
            .and_then(|path| fs::read_to_string(path).ok())
            .map(|text| parse_dotenv(&text))
            .unwrap_or_default();
        let get = |name: &str| {
            env::var(name)
                .ok()
                .or_else(|| values.get(name).cloned())
                .unwrap_or_default()
                .trim()
                .to_owned()
        };
        Self {
            abuseipdb_api_key: get("ABUSEIPDB_API_KEY"),
            virustotal_api_key: get("VIRUSTOTAL_API_KEY"),
            shodan_api_key: get("SHODAN_API_KEY"),
            greynoise_api_key: get("GREYNOISE_API_KEY"),
        }
    }

    pub fn key_for(&self, name: &str) -> &str {
        match name {
            "abuseipdb" => &self.abuseipdb_api_key,
            "virustotal" => &self.virustotal_api_key,
            "shodan" => &self.shodan_api_key,
            "greynoise" => &self.greynoise_api_key,
            _ => "",
        }
    }
}

fn local_env_file() -> Option<PathBuf> {
    let executable_dir = env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf));
    let current_dir = env::current_dir().ok();
    executable_dir
        .into_iter()
        .chain(current_dir)
        .map(|dir| dir.join(".env"))
        .find(|path| path.is_file())
}

fn parse_dotenv(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            let key = key.trim();
            if key.is_empty() {
                return None;
            }
            Some((
                key.to_owned(),
                value.trim().trim_matches('"').trim_matches('\'').to_owned(),
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_dotenv;

    #[test]
    fn dotenv_parser_keeps_keys_private_and_handles_quotes() {
        let values = parse_dotenv("# ignored\nA=\"one\"\nB='two'\n");
        assert_eq!(values.get("A").map(String::as_str), Some("one"));
        assert_eq!(values.get("B").map(String::as_str), Some("two"));
    }
}
