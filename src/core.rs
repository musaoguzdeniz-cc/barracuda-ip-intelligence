use serde_json::{Value, json};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn parse_ip(value: &str) -> Result<IpAddr, String> {
    value
        .trim()
        .parse::<IpAddr>()
        .map_err(|_| "Geçersiz IP adresi".to_owned())
}

fn v4_in(ip: Ipv4Addr, base: Ipv4Addr, bits: u32) -> bool {
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    (u32::from(ip) & mask) == (u32::from(base) & mask)
}

fn v6_in(ip: Ipv6Addr, base: Ipv6Addr, bits: u32) -> bool {
    let mask = if bits == 0 {
        0
    } else {
        u128::MAX << (128 - bits)
    };
    (u128::from(ip) & mask) == (u128::from(base) & mask)
}

pub fn classify_ip(ip: IpAddr) -> Value {
    let (version, private, loopback, link_local, multicast, reserved, unspecified, global) =
        match ip {
            IpAddr::V4(v) => {
                let private = v4_in(v, Ipv4Addr::new(10, 0, 0, 0), 8)
                    || v4_in(v, Ipv4Addr::new(172, 16, 0, 0), 12)
                    || v4_in(v, Ipv4Addr::new(192, 168, 0, 0), 16);
                let loopback = v4_in(v, Ipv4Addr::new(127, 0, 0, 0), 8);
                let link_local = v4_in(v, Ipv4Addr::new(169, 254, 0, 0), 16);
                let multicast = v4_in(v, Ipv4Addr::new(224, 0, 0, 0), 4);
                let reserved = v4_in(v, Ipv4Addr::new(240, 0, 0, 0), 4);
                let unspecified = v.is_unspecified();
                let other_bogon = [
                    (Ipv4Addr::new(0, 0, 0, 0), 8),
                    (Ipv4Addr::new(100, 64, 0, 0), 10),
                    (Ipv4Addr::new(192, 0, 0, 0), 24),
                    (Ipv4Addr::new(192, 0, 2, 0), 24),
                    (Ipv4Addr::new(198, 18, 0, 0), 15),
                    (Ipv4Addr::new(198, 51, 100, 0), 24),
                    (Ipv4Addr::new(203, 0, 113, 0), 24),
                ]
                .into_iter()
                .any(|(base, bits)| v4_in(v, base, bits));
                (
                    4,
                    private,
                    loopback,
                    link_local,
                    multicast,
                    reserved,
                    unspecified,
                    !(private
                        || loopback
                        || link_local
                        || multicast
                        || reserved
                        || unspecified
                        || other_bogon),
                )
            }
            IpAddr::V6(v) => {
                let private = v6_in(v, "fc00::".parse().unwrap(), 7);
                let loopback = v.is_loopback();
                let link_local = v6_in(v, "fe80::".parse().unwrap(), 10);
                let multicast = v.is_multicast();
                let unspecified = v.is_unspecified();
                let reserved = v6_in(v, "2001:db8::".parse().unwrap(), 32);
                let mapped_non_global = v
                    .to_ipv4_mapped()
                    .map(|mapped| {
                        !classify_ip(IpAddr::V4(mapped))["is_global"]
                            .as_bool()
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
                (
                    6,
                    private,
                    loopback,
                    link_local,
                    multicast,
                    reserved,
                    unspecified,
                    !(private
                        || loopback
                        || link_local
                        || multicast
                        || reserved
                        || unspecified
                        || mapped_non_global),
                )
            }
        };
    json!({
        "address": ip.to_string(),
        "version": version,
        "type": format!("IPv{version}"),
        "is_global": global,
        "is_private": private,
        "is_loopback": loopback,
        "is_link_local": link_local,
        "is_multicast": multicast,
        "is_reserved": reserved,
        "is_unspecified": unspecified,
        "is_bogon": !global,
    })
}

pub fn reverse_dns(ip: IpAddr) -> Value {
    match dns_lookup::lookup_addr(&ip) {
        Ok(hostname) => json!({
            "status": "ok",
            "hostname": hostname,
            "aliases": [],
            "addresses": [ip.to_string()],
        }),
        Err(_) => json!({
            "status": "not_found",
            "hostname": null,
            "error": "PTR kaydı bulunamadı",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_ip, parse_ip};

    #[test]
    fn classifies_global_and_bogon_addresses() {
        assert_eq!(classify_ip(parse_ip("8.8.8.8").unwrap())["is_global"], true);
        assert_eq!(
            classify_ip(parse_ip("192.168.1.5").unwrap())["is_bogon"],
            true
        );
        assert_eq!(
            classify_ip(parse_ip("100.64.0.1").unwrap())["is_global"],
            false
        );
        assert_eq!(
            classify_ip(parse_ip("2001:db8::1").unwrap())["is_global"],
            false
        );
        assert!(parse_ip("not-an-ip").is_err());
    }
}
