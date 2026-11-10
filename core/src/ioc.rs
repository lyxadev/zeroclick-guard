//! Indicator of Compromise (IoC): daftar domain & IP yang diketahui jahat.
//!
//! Ini versi DASAR yang open source. Feed IoC premium (ter-update &
//! terkurasi) adalah bagian berbayar — lihat docs/DESIGN.md. Formatnya tetap
//! sama, jadi engine tidak perlu tahu feed mana yang dipakai.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Satu entri IoC beserta konteksnya, agar alert bisa menjelaskan "kenapa".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IocEntry {
    /// Nilai indikator: alamat IP atau nama domain.
    pub value: String,
    /// Jenis: "ip" atau "domain".
    pub kind: String,
    /// Label ancaman yang bisa dibaca manusia, mis. "Infrastruktur C2 spyware".
    #[serde(default)]
    pub label: String,
    /// Sumber indikator (laporan/feed), untuk transparansi.
    #[serde(default)]
    pub source: String,
}

/// Kumpulan IoC yang bisa dicek dalam waktu konstan.
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
            _ => { /* jenis tak dikenal diabaikan */ }
        }
    }

    /// Muat daftar IoC dari teks JSON berisi array `IocEntry`.
    pub fn from_json(data: &str) -> Result<Self, serde_json::Error> {
        let entries: Vec<IocEntry> = serde_json::from_str(data)?;
        let mut set = IocSet::new();
        for e in entries {
            set.add(e);
        }
        Ok(set)
    }

    /// Cek apakah sebuah IP cocok dengan IoC.
    pub fn match_ip(&self, ip: &str) -> Option<&IocEntry> {
        self.ips.get(ip)
    }

    /// Cek apakah sebuah domain cocok dengan IoC (case-insensitive).
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
            {"value":"203.0.113.9","kind":"ip","label":"C2 uji","source":"testlab"},
            {"value":"evil.example","kind":"domain","label":"C2 uji","source":"testlab"}
        ]"#;
        let set = IocSet::from_json(json).unwrap();
        assert_eq!(set.len(), 2);
        assert!(set.match_ip("203.0.113.9").is_some());
        assert!(set.match_ip("8.8.8.8").is_none());
        assert!(set.match_domain("EVIL.EXAMPLE").is_some());
    }
}
