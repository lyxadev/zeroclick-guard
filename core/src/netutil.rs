//! Small network utilities — no external dependencies.

/// Does this IPv4 address belong to private/local space (not the public
/// Internet)?
///
/// Used to tell a "strange foreign connection" apart from local traffic
/// (router, LAN devices, localhost). IPv4 only for now; an address that cannot
/// be parsed is treated as public (safer for detection).
pub fn is_private_ipv4(ip: &str) -> bool {
    let octets: Vec<u8> = match parse_ipv4(ip) {
        Some(o) => o,
        None => return false,
    };
    let [a, b, _, _] = octets[..] else {
        return false;
    };
    match a {
        10 => true,                            // 10.0.0.0/8
        127 => true,                           // loopback
        169 if b == 254 => true,               // link-local 169.254.0.0/16
        172 if (16..=31).contains(&b) => true, // 172.16.0.0/12
        192 if b == 168 => true,               // 192.168.0.0/16
        _ => false,
    }
}

/// Is this destination "external" (public Internet)?
pub fn is_external(ip: &str) -> bool {
    !is_private_ipv4(ip) && !is_private_ipv6(ip)
}

fn is_private_ipv6(ip: &str) -> bool {
    let lower = ip.to_ascii_lowercase();
    lower == "::1"
        || lower.starts_with("fc")
        || lower.starts_with("fd")
        || lower.starts_with("fe80")
}

fn parse_ipv4(ip: &str) -> Option<Vec<u8>> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = Vec::with_capacity(4);
    for p in parts {
        out.push(p.parse::<u8>().ok()?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ranges() {
        assert!(is_private_ipv4("10.0.0.5"));
        assert!(is_private_ipv4("192.168.1.1"));
        assert!(is_private_ipv4("172.16.0.1"));
        assert!(is_private_ipv4("127.0.0.1"));
        assert!(!is_private_ipv4("203.0.113.9")); // TEST-NET-3, treated as external
        assert!(!is_private_ipv4("8.8.8.8"));
    }

    #[test]
    fn external_detection() {
        assert!(is_external("203.0.113.9"));
        assert!(!is_external("10.0.0.5"));
        assert!(!is_external("::1"));
    }

    #[test]
    fn unparseable_is_public() {
        // Parse failure → treat as public (safer for detection).
        assert!(!is_private_ipv4("not-an-ip"));
    }
}
