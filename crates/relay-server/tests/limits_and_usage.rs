//! Client IP selection for the registration limit, the Redis key forms of
//! 0.9.4 and the salted device hash of the statistics — without services.

use std::net::IpAddr;

use relay_server::config::{RelaySettings, parse_ip_list};
use relay_server::limits::{client_ip, registration_key};
use relay_server::maintenance::cleanup_lock_key;
use relay_server::usage::{Usage, device_hash, salt_key, year_month};
use uuid::Uuid;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn forwarded_for_is_only_believed_from_trusted_proxies() {
    let proxy = ip("10.0.0.2");
    let trusted = [proxy, ip("10.0.0.3")];
    // Direct connection: the header is ignored.
    assert_eq!(
        client_ip(Some(ip("203.0.113.7")), Some("198.51.100.1"), &trusted),
        Some(ip("203.0.113.7"))
    );
    // Through the proxy: the right-most untrusted hop is the client.
    assert_eq!(
        client_ip(Some(proxy), Some("198.51.100.1, 203.0.113.9"), &trusted),
        Some(ip("203.0.113.9"))
    );
    assert_eq!(
        client_ip(
            Some(proxy),
            Some("198.51.100.1, 203.0.113.9, 10.0.0.3"),
            &trusted
        ),
        Some(ip("203.0.113.9"))
    );
    // A forged left part cannot win; garbage stops at the last trusted hop.
    assert_eq!(
        client_ip(Some(proxy), Some("1.2.3.4, garbage"), &trusted),
        Some(proxy)
    );
    assert_eq!(client_ip(Some(proxy), None, &trusted), Some(proxy));
    assert_eq!(client_ip(None, Some("198.51.100.1"), &trusted), None);
    assert_eq!(
        client_ip(Some(ip("::1")), Some("2001:db8::1"), &[ip("::1")]),
        Some(ip("2001:db8::1"))
    );
}

#[test]
fn settings_defaults_are_the_spec_values() {
    let s = RelaySettings::default();
    assert_eq!(s.registrations_per_ip_per_hour, 10);
    assert_eq!(s.presence_refresh.as_secs(), 20);
    assert_eq!(s.ping_interval.as_secs(), 15);
    assert_eq!(s.pair_bandwidth_bytes_per_sec, 2 * 1024 * 1024);
    assert_eq!(s.usage_flush_interval.as_secs(), 60);
    assert_ne!(s.instance_id, RelaySettings::default().instance_id);
    assert_eq!(
        parse_ip_list(" 10.0.0.2, ::1 ,").unwrap(),
        vec![ip("10.0.0.2"), ip("::1")]
    );
    assert!(parse_ip_list("10.0.0.2, proxy").is_err());
}

#[test]
fn redis_key_forms() {
    assert_eq!(
        registration_key(&ip("203.0.113.7"), 480_000),
        "rl:ip:203.0.113.7:reg:480000"
    );
    // 2026-09-26T00:00:00Z = 1790380800000 ms, UTC day 20722.
    assert_eq!(cleanup_lock_key(1_790_380_800_000), "maintenance:20722");
    assert_eq!(salt_key(1_790_380_800_000), "usage_salt:2026-09");
}

#[test]
fn calendar_months_in_utc() {
    for (ms, expected) in [
        (0, (1970, 1)),
        (951_782_400_000, (2000, 2)),    // 2000-02-29
        (951_868_799_999, (2000, 2)),    // 2000-02-29T23:59:59.999Z
        (951_868_800_000, (2000, 3)),    // 2000-03-01
        (1_790_380_800_000, (2026, 9)),  // 2026-09-26
        (1_798_761_599_999, (2026, 12)), // 2026-12-31T23:59:59.999Z
        (1_798_761_600_000, (2027, 1)),  // 2027-01-01
        (-1, (1969, 12)),
    ] {
        assert_eq!(year_month(ms), expected, "{ms}");
    }
}

#[test]
fn device_hash_depends_on_the_monthly_salt() {
    let id = Uuid::parse_str("5b1f8c2e-9a4d-8e6f-a1b2-c3d4e5f60718").unwrap();
    let a = device_hash(&id, &[1; 32]);
    let b = device_hash(&id, &[2; 32]);
    assert_eq!(a.len(), 32);
    assert_ne!(a, b);
    assert_eq!(a, device_hash(&id, &[1; 32]));
    // Never the raw id.
    assert!(!a.windows(16).any(|w| w == id.as_bytes()));
}

#[test]
fn usage_tallies_add_up_and_restore() {
    let usage = Usage::default();
    let id = Uuid::new_v4();
    usage.add_envelope(id, 100);
    usage.add_envelope(id, 50);
    usage.add_push(id);
    let taken = usage.take();
    let t = taken[&id];
    assert_eq!((t.envelopes, t.bytes, t.pushes), (2, 150, 1));
    assert!(usage.take().is_empty());
    usage.restore(taken);
    usage.add_push(id);
    let t = usage.take()[&id];
    assert_eq!((t.envelopes, t.bytes, t.pushes), (2, 150, 2));
}
