//! Just enough JSON to write `manifest.json` exactly like nrfutil does.
//!
//! nrfutil serializes the manifest with Python's
//! `json.dumps(manifest, sort_keys=True, indent=4, separators=(',', ': '))`, which escapes all
//! non-ASCII characters. [`Value::to_json`] produces identical output.

use std::collections::BTreeMap;
use std::fmt::Write;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(u64),
    /// A number written verbatim, e.g. `0.5`.
    Number(&'static str),
    String(String),
    Array(Vec<Value>),
    /// Keys are kept sorted, as with `sort_keys=True`.
    Object(BTreeMap<&'static str, Value>),
}

impl Value {
    pub fn object<const N: usize>(entries: [(&'static str, Value); N]) -> Self {
        Value::Object(BTreeMap::from(entries))
    }

    pub fn to_json(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, 0);
        out
    }

    fn write(&self, out: &mut String, level: usize) {
        match self {
            Value::Int(n) => write!(out, "{n}").unwrap(),
            Value::Number(n) => out.push_str(n),
            Value::String(s) => write_string(out, s),
            Value::Array(items) if items.is_empty() => out.push_str("[]"),
            Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    newline(out, level + 1);
                    item.write(out, level + 1);
                }
                newline(out, level);
                out.push(']');
            }
            Value::Object(entries) if entries.is_empty() => out.push_str("{}"),
            Value::Object(entries) => {
                out.push('{');
                for (i, (key, value)) in entries.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    newline(out, level + 1);
                    write_string(out, key);
                    out.push_str(": ");
                    value.write(out, level + 1);
                }
                newline(out, level);
                out.push('}');
            }
        }
    }
}

impl From<u32> for Value {
    fn from(n: u32) -> Self {
        Value::Int(n.into())
    }
}

impl From<u16> for Value {
    fn from(n: u16) -> Self {
        Value::Int(n.into())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::String(s)
    }
}

fn newline(out: &mut String, level: usize) {
    out.push('\n');
    out.extend(std::iter::repeat_n(' ', 4 * level));
}

/// Writes a string literal the way Python's `json` module does with `ensure_ascii=True`.
fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            _ => {
                for unit in c.encode_utf16(&mut [0; 2]) {
                    write!(out, "\\u{unit:04x}").unwrap();
                }
            }
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_python_formatting() {
        let value = Value::object([
            ("b", Value::Array(vec![Value::Int(1), Value::Int(65534)])),
            (
                "a",
                Value::object([("z", Value::Number("0.5")), ("y", Value::Array(vec![]))]),
            ),
            ("c", Value::object([])),
        ]);
        // json.dumps({"b": [1, 65534], "a": {"z": 0.5, "y": []}, "c": {}},
        //            sort_keys=True, indent=4, separators=(',', ': '))
        let expected = "{\n    \"a\": {\n        \"y\": [],\n        \"z\": 0.5\n    },\n    \"b\": [\n        1,\n        65534\n    ],\n    \"c\": {}\n}";
        assert_eq!(value.to_json(), expected);
    }

    #[test]
    fn escapes_like_python() {
        let value = Value::String("q\"\\/\n\t\u{1}\u{7f}\u{fc}\u{20ac}\u{1f600}".to_owned());
        // json.dumps('q"\\/\n\t\x01\x7f\u00fc\u20ac\U0001F600')
        assert_eq!(
            value.to_json(),
            "\"q\\\"\\\\/\\n\\t\\u0001\\u007f\\u00fc\\u20ac\\ud83d\\ude00\""
        );
    }
}
