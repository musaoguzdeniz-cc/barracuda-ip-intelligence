use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;

pub fn write_json(report: &Value, path: &Path) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let content = serde_json::to_string_pretty(report).map_err(|error| error.to_string())?;
    fs::write(path, content).map_err(|error| error.to_string())
}

fn flatten(value: &Value, prefix: &str, row: &mut BTreeMap<String, String>) {
    match value {
        Value::Object(fields) => {
            for (key, item) in fields {
                let child = if prefix.is_empty() {
                    key.to_owned()
                } else {
                    format!("{prefix}.{key}")
                };
                flatten(item, &child, row);
            }
        }
        Value::Array(_) => {
            row.insert(prefix.to_owned(), value.to_string());
        }
        Value::Null => {
            row.insert(prefix.to_owned(), String::new());
        }
        Value::Bool(flag) => {
            row.insert(
                prefix.to_owned(),
                if *flag { "True" } else { "False" }.to_owned(),
            );
        }
        Value::String(text) => {
            row.insert(prefix.to_owned(), text.to_owned());
        }
        _ => {
            row.insert(prefix.to_owned(), value.to_string());
        }
    }
}

pub fn write_csv(report: &Value, path: &Path) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let mut row = BTreeMap::new();
    flatten(report, "", &mut row);
    let mut file = fs::File::create(path).map_err(|error| error.to_string())?;
    file.write_all(b"\xEF\xBB\xBF")
        .map_err(|error| error.to_string())?;
    let mut writer = csv::Writer::from_writer(file);
    writer
        .write_record(row.keys())
        .map_err(|error| error.to_string())?;
    writer
        .write_record(row.values())
        .map_err(|error| error.to_string())?;
    writer.flush().map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::flatten;
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn flattens_nested_report_fields() {
        let mut row = BTreeMap::new();
        flatten(
            &json!({"risk":{"score":5},"tags":["a","b"],"ready":true}),
            "",
            &mut row,
        );
        assert_eq!(row.get("risk.score").map(String::as_str), Some("5"));
        assert_eq!(row.get("tags").map(String::as_str), Some("[\"a\",\"b\"]"));
        assert_eq!(row.get("ready").map(String::as_str), Some("True"));
    }
}
