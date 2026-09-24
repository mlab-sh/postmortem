pub mod go;
pub mod java;
pub mod node;
pub mod php;
pub mod pnpm;
pub mod python;
pub mod ruby;
pub mod rust;
pub mod yarn;

use serde_yaml::Value;

/// A YAML mapping deserialised as `(key, value)` pairs in document order.
///
/// The YAML lockfile parsers (pnpm, Berry yarn) deserialise into typed structs
/// so the fields they never read — `engines`, `cpu`, `peerDependencies`,
/// tarball URLs, … — are skipped instead of built into a `serde_yaml::Value`
/// tree. Their maps must keep document order, though: it decides the order
/// parent edges are recorded in, and `serde_yaml::Mapping` (an index map) kept
/// it. A `BTreeMap`/`HashMap` would not, so this is a `Vec`.
///
/// A duplicate key is still an error, worded as `Mapping` words it: a lockfile
/// that states one key twice is malformed, and was reported as a parse failure.
pub(crate) struct YamlMap<V>(pub Vec<(Value, V)>);

impl<'de, V: serde::Deserialize<'de>> serde::Deserialize<'de> for YamlMap<V> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visit<V>(std::marker::PhantomData<V>);
        impl<'de, V: serde::Deserialize<'de>> serde::de::Visitor<'de> for Visit<V> {
            type Value = YamlMap<V>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a mapping")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut m: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out: Vec<(Value, V)> = Vec::with_capacity(m.size_hint().unwrap_or(0));
                while let Some(kv) = m.next_entry()? {
                    out.push(kv);
                }
                let mut seen = std::collections::HashSet::with_capacity(out.len());
                if let Some((k, _)) = out.iter().find(|(k, _)| !seen.insert(k)) {
                    let with = match k {
                        Value::Null => "with null key".to_string(),
                        Value::Bool(b) => format!("with key `{b}`"),
                        Value::Number(n) => format!("with key {n}"),
                        Value::String(s) => format!("with key {s:?}"),
                        _ => "in YAML map".to_string(),
                    };
                    return Err(serde::de::Error::custom(format!("duplicate entry {with}")));
                }
                Ok(YamlMap(out))
            }
        }
        d.deserialize_map(Visit(std::marker::PhantomData))
    }
}
