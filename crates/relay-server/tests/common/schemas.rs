//! The shared JSON Schemas (`../shared/schemas`, draft 2020-12), loaded
//! into one registry so their cross-file `$ref`s resolve offline.

use jsonschema::Registry;
use serde_json::{Value, json};

pub const BASE: &str = "https://handlive.app/schemas/v1/";

pub struct Schemas {
    registry: Registry<'static>,
}

impl Schemas {
    pub fn load() -> Self {
        let dir = format!("{}/../../../shared/schemas", env!("CARGO_MANIFEST_DIR"));
        let mut builder = Registry::new();
        let mut count = 0;
        for entry in std::fs::read_dir(&dir).expect("shared/schemas") {
            let path = entry.unwrap().path();
            if !path.to_string_lossy().ends_with(".schema.json") {
                continue;
            }
            let schema: Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            let id = schema["$id"].as_str().expect("$id").to_owned();
            builder = builder.add(id, schema).expect("schema uri");
            count += 1;
        }
        assert!(count >= 20, "only {count} schemas in {dir}");
        Self {
            registry: builder.prepare().expect("schema registry"),
        }
    }

    /// Errors of `value` against `<file>` or `<file>#<def>` (file name
    /// without `.schema.json`), as "<instance path>: <message>".
    pub fn errors(&self, target: &str, value: &Value) -> Vec<String> {
        let uri = match target.split_once('#') {
            Some((file, def)) => format!("{BASE}{file}.schema.json#/$defs/{def}"),
            None => format!("{BASE}{target}.schema.json"),
        };
        let validator = jsonschema::options()
            .with_registry(&self.registry)
            .build(&json!({ "$ref": uri }))
            .unwrap_or_else(|e| panic!("schema {target}: {e}"));
        validator
            .iter_errors(value)
            .map(|e| format!("{}: {e}", e.instance_path()))
            .collect()
    }

    pub fn check(&self, target: &str, value: &Value) {
        let errors = self.errors(target, value);
        assert!(errors.is_empty(), "{target} rejects {value}: {errors:#?}");
    }
}
