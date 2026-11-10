//! Indicator of Compromise (IoC): a list of known-bad domains & IPs.
//!
//! This is the BASIC, open-source list. A premium IoC feed (fresh & curated)
//! is the paid part — see docs/DESIGN.md. The format is the same either way,
//! so the engine does not need to know which feed is in use.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single IoC entry together with its context, so alerts can explain "why".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IocEntry {
    /// The indicator value: an IP address or a domain name.
    pub value: String,
    /// Kind: "ip" or "domain".
    pub kind: String,
    /// Human-readable threat label, e.g. "Spyware C2 infrastructure".
    #[serde(default)]
    pub label: String,
    /// Source of the indicator (report/feed), for transparency.
    #[serde(default)]
    pub source: String,
}

/// A set of IoCs that can be checked in constant time.
#[derive(Debug, Clone, Default)]
pub struct IocSet {
    ips: HashMap<String, IocEntry>,
    domains: HashMap<String, IocEntry>,
}

impl IocSet {
    pub fn new() -> Self {
        IocSet::default()
    }

    pub fn len(&self) -> usize {
        self.ips.len() + self.domains.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn add(&mut self, entry: IocEntry) {
        match entry.kind.as_str() {
            "ip" => {
                self.ips.insert(entry.value.clone(), entry);
            }
            "domain" => {
                self.domains.insert(entry.value.to_ascii_lowercase(), entry);
            }
            _ => { /* unknown kinds are ignored */ }
        }
    }

    /// Load an IoC list from JSON text containing an array of `IocEntry`.
    pub fn from_json(data: &str) -> Result<Self, serde_json::Error> {
        let entries: Vec<IocEntry> = serde_json::from_str(data)?;
        let mut set = IocSet::new();
        for e in entries {
            set.add(e);
        }
        Ok(set)
    }

    /// Check whether an IP matches an IoC.
    pub fn match_ip(&self, ip: &str) -> Option<&IocEntry> {
        self.ips.get(ip)
    }

    /// Check whether a domain matches an IoC (case-insensitive).
    pub fn match_domain(&self, domain: &str) -> Option<&IocEntry> {
        self.domains.get(&domain.to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_and_match() {
        let json = r#"[
            {"value":"203.0.113.9","kind":"ip","label":"test C2","source":"testlab"},
            {"value":"evil.example","kind":"domain","label":"test C2","source":"testlab"}
        ]"#;
        let set = IocSet::from_json(json).unwrap();
        assert_eq!(set.len(), 2);
        assert!(set.match_ip("203.0.113.9").is_some());
        assert!(set.match_ip("8.8.8.8").is_none());
        assert!(set.match_domain("EVIL.EXAMPLE").is_some());
    }
}
