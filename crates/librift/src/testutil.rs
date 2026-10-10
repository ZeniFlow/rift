//! Общие помощники для тестов: цепочка доверия, свидетель, голые ноды.

use iroh::{RelayMode, SecretKey};
use rift_trust::{
    Bundle, ControlCert, DnsRecords, DomainRecord, PublicKey, Record, Signed, Time, Trust, ZoneCert, log::logged_now,
};

use crate::{Config, Handler, Node, names::now};

pub const DAY: Time = 86_400;

/// Единственный свидетель всех тестов.
pub fn witness() -> &'static SecretKey {
    static W: std::sync::OnceLock<SecretKey> = std::sync::OnceLock::new();
    W.get_or_init(SecretKey::generate)
}

pub fn trust(root: &SecretKey) -> Trust {
    Trust { root: root.public(), witnesses: vec![witness().public()], threshold: 1 }
}

/// Цепочка root → control → зона `brand` (владелец зоны сам регистрирует) → shop.brand → хост.
pub fn bundle(root: &SecretKey, control: &SecretKey, zone: &SecretKey, owner: &SecretKey, host: PublicKey, seq: u64) -> Bundle {
    let (t, name) = (now() - 60, "shop.brand".to_string());
    let zone_cert = Signed::sign(ZoneCert { zone: "brand".into(), owner: zone.public(), issued_at: t, expires_at: t + 700 * DAY }, control);
    let domain = Signed::sign(DomainRecord { name: name.clone(), owner: owner.public(), issued_at: t, expires_at: t + 300 * DAY }, zone);
    Bundle {
        control: Signed::sign(ControlCert { key: control.public(), issued_at: t, expires_at: t + 90 * DAY }, root),
        zone: logged_now(control, zone_cert, t + 1, &[witness()]),
        registrar: None,
        domain: logged_now(zone, domain, t + 1, &[witness()]),
        dns: Signed::sign(DnsRecords { name, seq, records: vec![Record::Host(host)], issued_at: t, expires_at: t + 30 * DAY }, owner),
    }
}

/// Нода без relay и mDNS, только прямые адреса: для тестов в одном процессе.
pub async fn node(extra: Vec<(Vec<u8>, Handler)>) -> Node {
    Node::bind(Config {
        key: SecretKey::generate(),
        relay_mode: RelayMode::Disabled,
        lan: false,
        proxy: None,
        bridge: None,
        relay_ca: None,
        vpn: None,
        extra,
    })
    .await
    .unwrap()
}
