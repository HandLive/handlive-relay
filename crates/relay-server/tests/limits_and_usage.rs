//! Client IP selection for the registration limit, the Redis key forms of
//! 0.9.4 and the salted device hash of the statistics — without services.

use std::net::IpAddr;

use relay_server::config::{
    RelaySettings, effective_trusted_proxies, parse_ip_list, proxy_warning,
};
use relay_server::limits::{
    OnceAMinute, auth_ip_key, challenge_quota_key, client_ip, forwarded_for_ignored,
    global_registration_key, ip_bucket, registration_key,
};
use relay_server::maintenance::cleanup_lock_key;
use relay_server::store::challenges::challenge_key;
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
fn ipv4_mapped_addresses_compare_as_ipv4() {
    let trusted = parse_ip_list("::ffff:10.0.0.2").unwrap();
    assert_eq!(trusted, vec![ip("10.0.0.2")]);
    // A dual-stack listener reports the proxy as ::ffff:10.0.0.2.
    assert_eq!(
        client_ip(
            Some(ip("::ffff:10.0.0.2")),
            Some("198.51.100.1"),
            &[ip("10.0.0.2")]
        ),
        Some(ip("198.51.100.1"))
    );
    // A trusted list written by hand with the mapped form still matches.
    assert_eq!(
        client_ip(
            Some(ip("10.0.0.2")),
            Some("198.51.100.1"),
            &[ip("::ffff:10.0.0.2")]
        ),
        Some(ip("198.51.100.1"))
    );
    // Hops are normalized too: a mapped trusted hop is skipped, a mapped
    // client comes out as IPv4.
    assert_eq!(
        client_ip(
            Some(ip("10.0.0.2")),
            Some("::ffff:198.51.100.1, ::ffff:10.0.0.3"),
            &[ip("10.0.0.2"), ip("10.0.0.3")]
        ),
        Some(ip("198.51.100.1"))
    );
    assert_eq!(
        client_ip(Some(ip("::ffff:203.0.113.7")), None, &[]),
        Some(ip("203.0.113.7"))
    );
}

#[test]
fn settings_defaults_are_the_spec_values() {
    let s = RelaySettings::default();
    assert_eq!(s.registrations_per_ip_per_hour, 10);
    assert_eq!(s.max_registrations_per_hour, 1_000);
    assert_eq!(s.presence_refresh.as_secs(), 20);
    assert_eq!(s.ping_interval.as_secs(), 15);
    assert_eq!(s.pair_bandwidth_bytes_per_sec, 2 * 1024 * 1024);
    assert_eq!(s.usage_flush_interval.as_secs(), 60);
    assert_eq!(s.idle_timeout.as_secs(), 45);
    assert_eq!(s.max_queued_bytes, 32 * 1024 * 1024);
    assert_eq!(s.write_timeout.as_secs(), 10);
    assert_ne!(s.instance_id, RelaySettings::default().instance_id);
    assert_eq!(
        parse_ip_list(" 10.0.0.2, ::1 ,").unwrap(),
        vec![ip("10.0.0.2"), ip("::1")]
    );
    assert!(parse_ip_list("10.0.0.2, proxy").is_err());
}

#[test]
fn startup_warns_about_a_public_bind_without_trusted_proxies() {
    for bind in [
        "0.0.0.0:8080",
        "[::]:8080",
        "203.0.113.7:443",
        "relay.example.com:8080",
    ] {
        assert!(proxy_warning(bind, &[]).is_some(), "{bind}");
        assert_eq!(proxy_warning(bind, &[ip("10.0.0.2")]), None, "{bind}");
    }
    for bind in [
        "127.0.0.1:8080",
        "[::1]:8080",
        "localhost:8080",
        "127.0.0.2:1",
    ] {
        assert_eq!(proxy_warning(bind, &[]), None, "{bind}");
    }
}

#[test]
fn a_loopback_relay_trusts_the_local_proxy_by_default() {
    let local = vec![ip("127.0.0.1"), ip("::1")];
    for bind in ["127.0.0.1:8080", "[::1]:8080", "localhost:8080"] {
        assert_eq!(effective_trusted_proxies(bind, Vec::new()), local, "{bind}");
        // An explicit list always wins.
        assert_eq!(
            effective_trusted_proxies(bind, vec![ip("10.0.0.2")]),
            vec![ip("10.0.0.2")]
        );
    }
    for bind in ["0.0.0.0:8080", "[::]:8080", "relay.example.com:8080"] {
        assert!(
            effective_trusted_proxies(bind, Vec::new()).is_empty(),
            "{bind}"
        );
    }
    // Behind nginx on the same host, the forwarded client counts.
    let trusted = effective_trusted_proxies("127.0.0.1:8080", Vec::new());
    assert_eq!(
        client_ip(Some(ip("::ffff:127.0.0.1")), Some("203.0.113.9"), &trusted),
        Some(ip("203.0.113.9"))
    );
}

#[test]
fn untrusted_forwarded_for_is_reported_at_most_once_a_minute() {
    let trusted = [ip("10.0.0.2")];
    assert!(forwarded_for_ignored(
        Some(ip("203.0.113.7")),
        Some("198.51.100.1"),
        &trusted
    ));
    assert!(!forwarded_for_ignored(
        Some(ip("203.0.113.7")),
        None,
        &trusted
    ));
    assert!(!forwarded_for_ignored(
        Some(ip("::ffff:10.0.0.2")),
        Some("198.51.100.1"),
        &trusted
    ));
    assert!(!forwarded_for_ignored(None, Some("198.51.100.1"), &trusted));

    let gate = OnceAMinute::default();
    let t = 1_727_160_000_000_i64;
    assert!(gate.due(t));
    assert!(!gate.due(t + 1));
    assert!(!gate.due(t + 59_999));
    assert!(gate.due(t + 60_000));
    assert!(!gate.due(t + 60_001));
}

#[test]
fn redis_key_forms() {
    assert_eq!(
        registration_key(&ip("203.0.113.7"), 480_000),
        "rl:ip:203.0.113.7:reg:480000"
    );
    // 2026-09-26T00:00:00Z = 1790380800000 ms, UTC day 20722.
    // IPv6 clients count per /64 in every `rl:ip:` key.
    assert_eq!(
        registration_key(&ip("2001:db8:1:2:aaaa::7"), 480_000),
        "rl:ip:2001:db8:1:2::/64:reg:480000"
    );
    assert_eq!(global_registration_key(480_000), "rl:reg:480000");
    assert_eq!(
        auth_ip_key(&ip("203.0.113.7"), 28_800_000),
        "rl:ip:203.0.113.7:auth:28800000"
    );
    assert_eq!(
        auth_ip_key(&ip("2001:db8:1:2:ffff:1:2:3"), 28_800_000),
        "rl:ip:2001:db8:1:2::/64:auth:28800000"
    );
    let device = Uuid::parse_str("5b1f8c2e-9a4d-8e6f-a1b2-c3d4e5f60718").unwrap();
    assert_eq!(
        challenge_quota_key(&device, Some(&ip("2001:db8::9")), 28_800_000),
        "rl:5b1f8c2e-9a4d-8e6f-a1b2-c3d4e5f60718:2001:db8::/64:chal:28800000"
    );
    assert_eq!(
        challenge_quota_key(&device, None, 1),
        "rl:5b1f8c2e-9a4d-8e6f-a1b2-c3d4e5f60718:unknown:chal:1"
    );
    // One key per pending challenge.
    assert_eq!(
        challenge_key(&device, &[0u8; 32]),
        "chal:5b1f8c2e-9a4d-8e6f-a1b2-c3d4e5f60718:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
    assert_eq!(cleanup_lock_key(1_790_380_800_000), "maintenance:20722");
    assert_eq!(salt_key(1_790_380_800_000), "usage_salt:2026-09");
}

#[test]
fn ipv6_clients_are_bucketed_per_64() {
    assert_eq!(ip_bucket(&ip("198.51.100.4")), "198.51.100.4");
    assert_eq!(ip_bucket(&ip("2001:db8:a:b:c:d:e:f")), "2001:db8:a:b::/64");
    assert_eq!(
        ip_bucket(&ip("2001:db8:a:b::1")),
        ip_bucket(&ip("2001:db8:a:b:ffff:ffff:ffff:ffff"))
    );
    assert_ne!(
        ip_bucket(&ip("2001:db8:a:b::1")),
        ip_bucket(&ip("2001:db8:a:c::1"))
    );
    // An IPv4-mapped IPv6 address is the IPv4 client.
    assert_eq!(ip_bucket(&ip("::ffff:198.51.100.4")), "198.51.100.4");
    assert_eq!(ip_bucket(&ip("::1")), "::/64");
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
