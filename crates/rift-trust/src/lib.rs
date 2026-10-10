//! Модель доверия Rift (docs/trust.md). Всё проверяется оффлайн, без связи с control.
//!
//! ```text
//! root ─► ControlCert ─► ZoneCert ─► [RegistrarCert] ─► DomainRecord ─► DnsRecords
//!                                                       (подписывает      (подписывает
//!                                                        регистратор или   владелец
//!                                                        владелец зоны)    домена)
//! ```
//!
//! Подпись — Ed25519 над `"rift-trust/v1/<вид>\0" || JSON(body)`. JSON детерминирован: поля идут
//! в порядке объявления структур, карт нет.
//!
//! ponytail: время выпуска (`issued_at`) подписывает сам выпускающий, поэтому задним числом
//! его не поймать. Лечится transparency-логом (trust.md §3): время = время головы лога.

use std::fmt;

pub use iroh_base::{PublicKey, SecretKey, Signature};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub type Time = u64; // unix-секунды

// ---------------------------------------------------------------- подписанные тела

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlCert {
    pub key: PublicKey,
    pub issued_at: Time,
    /// Только окно выпуска: зоны, выданные до этого момента, живут дальше (trust.md §4).
    pub expires_at: Time,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneCert {
    /// Одна метка: `brand`, не `a.brand`.
    pub zone: String,
    pub owner: PublicKey,
    pub issued_at: Time,
    pub expires_at: Time,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrarCert {
    pub zone: String,
    pub registrar: PublicKey,
    pub issued_at: Time,
    pub expires_at: Time,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRecord {
    /// `<метка>.<зона>`
    pub name: String,
    pub owner: PublicKey,
    pub issued_at: Time,
    pub expires_at: Time,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Record {
    /// NodeID хоста, который отдаёт сайт.
    Host(PublicKey),
    Txt(String),
}

/// Подписывает ВЛАДЕЛЕЦ ДОМЕНА: ни регистратор, ни владелец зоны, ни control подменить не могут.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecords {
    pub name: String,
    /// Растёт с каждой публикацией; при нескольких копиях побеждает большая.
    pub seq: u64,
    pub records: Vec<Record>,
    pub issued_at: Time,
    pub expires_at: Time,
}

/// Объявления control (или root, если отзывается сам control). Публикуются в логе.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Notice {
    /// Ключ украден: всё, что он выдал начиная с `since`, недействительно.
    RevokeKey { key: PublicKey, since: Time },
    /// Зона отозвана целиком.
    RevokeZone { zone: String, since: Time },
    /// Takedown: домен не резолвится.
    Freeze { name: String, since: Time },
}

/// Объявление + кем подписано. Control ротируется, поэтому объявление несёт СВОЙ сертификат control
/// (его проверяют по root), а не полагается на control из цепочки домена. `None` — подписал сам root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Announcement {
    pub notice: Signed<Notice>,
    pub control: Option<Signed<ControlCert>>,
}

impl Announcement {
    pub fn valid(&self, root: &PublicKey) -> bool {
        match &self.control {
            None => self.notice.verify(root),
            Some(c) => c.verify(root) && self.notice.verify(&c.body.key),
        }
    }
}

// ---------------------------------------------------------------- подписи

pub trait Kind {
    const KIND: &'static str;
}
macro_rules! kinds { ($($t:ty => $k:literal),*) => {$(impl Kind for $t { const KIND: &'static str = $k; })*} }
kinds!(ControlCert => "control", ZoneCert => "zone", RegistrarCert => "registrar",
       DomainRecord => "domain", DnsRecords => "dns", Notice => "notice");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signed<T> {
    pub body: T,
    pub sig: Signature,
}

impl<T: Kind + Serialize> Signed<T> {
    fn message(body: &T) -> Vec<u8> {
        let mut m = format!("rift-trust/v1/{}\0", T::KIND).into_bytes();
        m.extend(serde_json::to_vec(body).expect("тело сериализуется"));
        m
    }

    pub fn sign(body: T, key: &SecretKey) -> Self {
        let sig = key.sign(&Self::message(&body));
        Self { body, sig }
    }

    pub fn verify(&self, signer: &PublicKey) -> bool {
        signer.verify(&Self::message(&self.body), &self.sig).is_ok()
    }
}

// ---------------------------------------------------------------- имена

pub fn valid_label(s: &str) -> bool {
    (1..=63).contains(&s.len())
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `shop.brand` → (`shop`, `brand`). ponytail: только ASCII и ровно две метки; IDN и поддомены позже.
pub fn split_name(name: &str) -> Option<(&str, &str)> {
    let (label, zone) = name.split_once('.')?;
    (valid_label(label) && valid_label(zone)).then_some((label, zone))
}

// ---------------------------------------------------------------- цепочка

/// Всё, что хост показывает клиенту (как цепочка сертификатов в TLS).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    pub control: Signed<ControlCert>,
    pub zone: Signed<ZoneCert>,
    /// Нет, если домен зарегистрировал сам владелец зоны.
    pub registrar: Option<Signed<RegistrarCert>>,
    pub domain: Signed<DomainRecord>,
    pub dns: Signed<DnsRecords>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub name: String,
    pub owner: PublicKey,
    pub hosts: Vec<PublicKey>,
    pub txt: Vec<String>,
    pub seq: u64,
    /// До какого момента ответ годится без перепроверки.
    pub valid_until: Time,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    BadSignature(&'static str),
    BadName(String),
    Expired(&'static str),
    NotYetValid(&'static str),
    /// Сертификат выпущен вне окна действия родителя.
    OutsideParentWindow(&'static str),
    Mismatch(&'static str),
    Revoked(&'static str),
    Frozen(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadSignature(w) => write!(f, "неверная подпись: {w}"),
            Error::BadName(n) => write!(f, "недопустимое имя: {n}"),
            Error::Expired(w) => write!(f, "истёк срок: {w}"),
            Error::NotYetValid(w) => write!(f, "ещё не действует: {w}"),
            Error::OutsideParentWindow(w) => write!(f, "{w} выпущен вне срока родителя"),
            Error::Mismatch(w) => write!(f, "не сходится: {w}"),
            Error::Revoked(w) => write!(f, "отозван: {w}"),
            Error::Frozen(n) => write!(f, "{n} заморожен control"),
        }
    }
}
impl std::error::Error for Error {}

type R<T> = Result<T, Error>;

fn within(t: Time, from: Time, to: Time) -> bool {
    from <= t && t <= to
}

fn live(what: &'static str, issued: Time, expires: Time, now: Time) -> R<()> {
    if now < issued {
        return Err(Error::NotYetValid(what));
    }
    if now >= expires {
        return Err(Error::Expired(what));
    }
    Ok(())
}

/// Полная проверка. `root` вшит в клиент. `notices` — всё, что известно об отзывах;
/// объявления с неверной подписью молча игнорируются (мусор не должен ломать резолв).
pub fn verify(root: &PublicKey, b: &Bundle, notices: &[Announcement], now: Time) -> R<Resolved> {
    let (control, zone, dom, dns) = (&b.control.body, &b.zone.body, &b.domain.body, &b.dns.body);

    // 1. подписи по цепочке
    if !b.control.verify(root) {
        return Err(Error::BadSignature("control (не root)"));
    }
    if !b.zone.verify(&control.key) {
        return Err(Error::BadSignature("зона (не control)"));
    }
    let domain_signer = match &b.registrar {
        Some(r) => {
            if !r.verify(&zone.owner) {
                return Err(Error::BadSignature("регистратор (не владелец зоны)"));
            }
            if r.body.zone != zone.zone {
                return Err(Error::Mismatch("зона регистратора"));
            }
            r.body.registrar
        }
        None => zone.owner,
    };
    if !b.domain.verify(&domain_signer) {
        return Err(Error::BadSignature("домен (не регистратор / владелец зоны)"));
    }
    if !b.dns.verify(&dom.owner) {
        return Err(Error::BadSignature("записи (не владелец домена)"));
    }

    // 2. имена
    let (_, zname) = split_name(&dom.name).ok_or_else(|| Error::BadName(dom.name.clone()))?;
    if zname != zone.zone || !valid_label(&zone.zone) {
        return Err(Error::Mismatch("домен вне зоны"));
    }
    if dns.name != dom.name {
        return Err(Error::Mismatch("имя в записях"));
    }

    // 3. вложенность окон: ребёнок выпущен, пока родитель действовал
    if !within(zone.issued_at, control.issued_at, control.expires_at) {
        return Err(Error::OutsideParentWindow("зона"));
    }
    if let Some(r) = &b.registrar {
        if !within(r.body.issued_at, zone.issued_at, zone.expires_at) {
            return Err(Error::OutsideParentWindow("регистратор"));
        }
        if !within(dom.issued_at, r.body.issued_at, r.body.expires_at) {
            return Err(Error::OutsideParentWindow("домен"));
        }
    } else if !within(dom.issued_at, zone.issued_at, zone.expires_at) {
        return Err(Error::OutsideParentWindow("домен"));
    }
    if !within(dns.issued_at, dom.issued_at, dom.expires_at) {
        return Err(Error::OutsideParentWindow("записи"));
    }

    // 4. сроки сейчас. Control не проверяем: его срок — окно выпуска (trust.md §4).
    live("зона", zone.issued_at, zone.expires_at, now)?;
    if let Some(r) = &b.registrar {
        live("регистратор", r.body.issued_at, r.body.expires_at, now)?;
    }
    live("домен", dom.issued_at, dom.expires_at, now)?;
    live("записи", dns.issued_at, dns.expires_at, now)?;

    // 5. объявления: подписаны root или любым control, которого признаёт root
    for n in notices {
        if !n.valid(root) {
            continue;
        }
        match &n.notice.body {
            Notice::Freeze { name, since } if *name == dom.name && *since <= now => {
                return Err(Error::Frozen(dom.name.clone()));
            }
            Notice::RevokeZone { zone: z, since } if *z == zone.zone && *since <= now => {
                return Err(Error::Revoked("зона"));
            }
            Notice::RevokeKey { key, since } => {
                let hit = |signer: &PublicKey, issued: Time, what| {
                    (signer == key && issued >= *since).then_some(Error::Revoked(what))
                };
                let found = hit(root, control.issued_at, "root")
                    .or_else(|| hit(&control.key, zone.issued_at, "ключ control"))
                    .or_else(|| hit(&zone.owner, b.registrar.as_ref().map_or(dom.issued_at, |r| r.body.issued_at), "ключ владельца зоны"))
                    .or_else(|| b.registrar.as_ref().and_then(|r| hit(&r.body.registrar, dom.issued_at, "ключ регистратора")))
                    .or_else(|| hit(&dom.owner, dns.issued_at, "ключ владельца домена"));
                if let Some(e) = found {
                    return Err(e);
                }
            }
            _ => {}
        }
    }

    let valid_until = [Some(zone.expires_at), b.registrar.as_ref().map(|r| r.body.expires_at), Some(dom.expires_at), Some(dns.expires_at)]
        .into_iter()
        .flatten()
        .min()
        .unwrap();
    Ok(Resolved {
        name: dom.name.clone(),
        owner: dom.owner,
        hosts: dns.records.iter().filter_map(|r| if let Record::Host(k) = r { Some(*k) } else { None }).collect(),
        txt: dns.records.iter().filter_map(|r| if let Record::Txt(t) = r { Some(t.clone()) } else { None }).collect(),
        seq: dns.seq,
        valid_until,
    })
}

/// Из нескольких копий одного домена оставляет проверенную с наибольшим `seq`.
pub fn newest(copies: impl IntoIterator<Item = Resolved>) -> Option<Resolved> {
    copies.into_iter().max_by_key(|r| r.seq)
}

// ---------------------------------------------------------------- файлы

pub fn to_json<T: Serialize>(v: &T) -> String {
    serde_json::to_string_pretty(v).expect("сериализуется")
}

pub fn from_json<T: DeserializeOwned>(s: &str) -> serde_json::Result<T> {
    serde_json::from_str(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: Time = 86_400;
    const T0: Time = 1_000_000;

    struct World {
        root: SecretKey,
        control: SecretKey,
        zone_owner: SecretKey,
        registrar: SecretKey,
        owner: SecretKey,
        host: SecretKey,
    }

    fn world() -> World {
        let k = SecretKey::generate;
        World { root: k(), control: k(), zone_owner: k(), registrar: k(), owner: k(), host: k() }
    }

    /// control 90 дней, зона 2 года, регистратор 1 год, домен/записи 1 год — всё выпущено в T0.
    fn bundle(w: &World, via_registrar: bool) -> Bundle {
        let control = Signed::sign(
            ControlCert { key: w.control.public(), issued_at: T0, expires_at: T0 + 90 * DAY },
            &w.root,
        );
        let zone = Signed::sign(
            ZoneCert { zone: "brand".into(), owner: w.zone_owner.public(), issued_at: T0, expires_at: T0 + 730 * DAY },
            &w.control,
        );
        let registrar = via_registrar.then(|| {
            Signed::sign(
                RegistrarCert { zone: "brand".into(), registrar: w.registrar.public(), issued_at: T0, expires_at: T0 + 365 * DAY },
                &w.zone_owner,
            )
        });
        let domain_signer = if via_registrar { &w.registrar } else { &w.zone_owner };
        let domain = Signed::sign(
            DomainRecord { name: "shop.brand".into(), owner: w.owner.public(), issued_at: T0, expires_at: T0 + 365 * DAY },
            domain_signer,
        );
        let dns = Signed::sign(
            DnsRecords {
                name: "shop.brand".into(),
                seq: 1,
                records: vec![Record::Host(w.host.public()), Record::Txt("hi".into())],
                issued_at: T0,
                expires_at: T0 + 30 * DAY,
            },
            &w.owner,
        );
        Bundle { control, zone, registrar, domain, dns }
    }

    fn ok(w: &World, b: &Bundle, n: &[Announcement], now: Time) -> Result<Resolved, Error> {
        verify(&w.root.public(), b, n, now)
    }

    #[test]
    fn resolves_via_registrar_and_directly_from_zone_owner() {
        let w = world();
        for via_registrar in [true, false] {
            let r = ok(&w, &bundle(&w, via_registrar), &[], T0 + DAY).unwrap();
            assert_eq!(r.name, "shop.brand");
            assert_eq!(r.hosts, vec![w.host.public()]);
            assert_eq!(r.txt, vec!["hi".to_string()]);
            assert_eq!(r.owner, w.owner.public());
            assert_eq!(r.valid_until, T0 + 30 * DAY);
        }
    }

    #[test]
    fn control_may_be_long_dead() {
        // Control-сертификат истёк 90 дней назад — домен всё равно резолвится (control «умер»).
        let w = world();
        let mut b = bundle(&w, true);
        b.dns = Signed::sign(
            DnsRecords { expires_at: T0 + 300 * DAY, ..b.dns.body.clone() },
            &w.owner,
        );
        assert!(ok(&w, &b, &[], T0 + 200 * DAY).is_ok());
    }

    #[test]
    fn wrong_root_or_any_wrong_signer_is_rejected() {
        let w = world();
        let b = bundle(&w, true);
        let other = SecretKey::generate().public();
        assert!(matches!(verify(&other, &b, &[], T0), Err(Error::BadSignature(_))));

        let stranger = SecretKey::generate();
        let mut x = b.clone();
        x.control = Signed::sign(x.control.body.clone(), &stranger);
        assert!(matches!(ok(&w, &x, &[], T0), Err(Error::BadSignature(_))));
        let mut x = b.clone();
        x.zone = Signed::sign(x.zone.body.clone(), &stranger);
        assert!(matches!(ok(&w, &x, &[], T0), Err(Error::BadSignature(_))));
        let mut x = b.clone();
        x.registrar = Some(Signed::sign(x.registrar.unwrap().body, &stranger));
        assert!(matches!(ok(&w, &x, &[], T0), Err(Error::BadSignature(_))));
        let mut x = b.clone();
        x.domain = Signed::sign(x.domain.body.clone(), &stranger);
        assert!(matches!(ok(&w, &x, &[], T0), Err(Error::BadSignature(_))));
        // Записи не может подписать ни регистратор, ни владелец зоны — только владелец домена.
        for k in [&w.registrar, &w.zone_owner, &w.control, &w.root] {
            let mut x = b.clone();
            x.dns = Signed::sign(x.dns.body.clone(), k);
            assert!(matches!(ok(&w, &x, &[], T0), Err(Error::BadSignature(_))));
        }
    }

    #[test]
    fn tampering_breaks_signature() {
        let w = world();
        let mut b = bundle(&w, true);
        b.dns.body.records = vec![Record::Host(SecretKey::generate().public())];
        assert!(matches!(ok(&w, &b, &[], T0), Err(Error::BadSignature(_))));
        let mut b = bundle(&w, true);
        b.zone.body.owner = SecretKey::generate().public();
        assert!(matches!(ok(&w, &b, &[], T0), Err(Error::BadSignature(_))));
    }

    #[test]
    fn registrar_cannot_sell_outside_its_zone_or_without_cert() {
        let w = world();
        // Регистратор зоны `other` продаёт имя в `brand`.
        let mut b = bundle(&w, true);
        b.registrar = Some(Signed::sign(
            RegistrarCert { zone: "other".into(), ..b.registrar.unwrap().body },
            &w.zone_owner,
        ));
        assert!(matches!(ok(&w, &b, &[], T0), Err(Error::Mismatch(_))));
        // Домен вне зоны.
        let mut b = bundle(&w, false);
        b.domain = Signed::sign(DomainRecord { name: "shop.evil".into(), ..b.domain.body }, &w.zone_owner);
        b.dns = Signed::sign(DnsRecords { name: "shop.evil".into(), ..b.dns.body }, &w.owner);
        assert!(matches!(ok(&w, &b, &[], T0), Err(Error::Mismatch(_))));
        // Регистратор без сертификата: подпись не сойдётся с владельцем зоны.
        let mut b = bundle(&w, true);
        b.registrar = None;
        assert!(matches!(ok(&w, &b, &[], T0), Err(Error::BadSignature(_))));
    }

    #[test]
    fn names_are_validated() {
        assert_eq!(split_name("shop.brand"), Some(("shop", "brand")));
        for bad in ["shop", "a.b.c", ".brand", "shop.", "Shop.brand", "-a.brand", "a-.brand", "sh op.brand", "shop.рф"] {
            assert_eq!(split_name(bad), None, "{bad}");
        }
        assert!(!valid_label(&"a".repeat(64)));
    }

    #[test]
    fn expiry_and_windows() {
        let w = world();
        let b = bundle(&w, true);
        assert!(matches!(ok(&w, &b, &[], T0 - 1), Err(Error::NotYetValid(_))));
        assert!(matches!(ok(&w, &b, &[], T0 + 30 * DAY), Err(Error::Expired("записи"))));

        // Зона выпущена уже после окончания control → её выпустил «мёртвый» control.
        let mut b = bundle(&w, true);
        b.zone = Signed::sign(ZoneCert { issued_at: T0 + 91 * DAY, ..b.zone.body }, &w.control);
        assert!(matches!(ok(&w, &b, &[], T0 + 92 * DAY), Err(Error::OutsideParentWindow("зона"))));

        // Домен живёт не дольше зоны.
        let mut b = bundle(&w, false);
        b.zone = Signed::sign(ZoneCert { expires_at: T0 + 10 * DAY, ..b.zone.body }, &w.control);
        assert!(matches!(ok(&w, &b, &[], T0 + 11 * DAY), Err(Error::Expired("зона"))));

        // Записи выпущены раньше домена.
        let mut b = bundle(&w, true);
        b.dns = Signed::sign(DnsRecords { issued_at: T0 - 1, ..b.dns.body }, &w.owner);
        assert!(matches!(ok(&w, &b, &[], T0), Err(Error::OutsideParentWindow("записи"))));
    }

    #[test]
    fn notices() {
        let w = world();
        let b = bundle(&w, true);
        let now = T0 + 5 * DAY;
        let by_control = |n| Announcement { notice: Signed::sign(n, &w.control), control: Some(b.control.clone()) };

        // Freeze / RevokeZone
        let freeze = by_control(Notice::Freeze { name: "shop.brand".into(), since: T0 + DAY });
        assert!(matches!(ok(&w, &b, &[freeze.clone()], now), Err(Error::Frozen(_))));
        assert!(ok(&w, &b, &[freeze], T0).is_ok()); // ещё не заморожен
        let rz = by_control(Notice::RevokeZone { zone: "brand".into(), since: T0 });
        assert!(matches!(ok(&w, &b, &[rz], now), Err(Error::Revoked(_))));

        // Украден ключ владельца зоны: регистратор, выданный с `since`, недействителен; до `since` — ок.
        let leak = |since| by_control(Notice::RevokeKey { key: w.zone_owner.public(), since });
        assert!(matches!(ok(&w, &b, &[leak(T0)], now), Err(Error::Revoked(_))));
        assert!(ok(&w, &b, &[leak(T0 + 1)], now).is_ok());
        // Украден ключ control: root отзывает его, зона выпущена после since → недействительна.
        let root_rev = Announcement {
            notice: Signed::sign(Notice::RevokeKey { key: w.control.public(), since: T0 }, &w.root),
            control: None,
        };
        assert!(matches!(ok(&w, &b, &[root_rev], now), Err(Error::Revoked(_))));

        // Ротация: control-2 (выпущен root) замораживает домен из цепочки control-1 — действует.
        let control2 = SecretKey::generate();
        let cert2 = Signed::sign(ControlCert { key: control2.public(), issued_at: T0 + DAY, expires_at: T0 + 91 * DAY }, &w.root);
        let by_2 = Announcement {
            notice: Signed::sign(Notice::Freeze { name: "shop.brand".into(), since: T0 + 2 * DAY }, &control2),
            control: Some(cert2),
        };
        assert!(matches!(ok(&w, &b, &[by_2], T0 + 3 * DAY), Err(Error::Frozen(_))));

        // Мусор игнорируется: подпись постороннего; control-сертификат не от root; испорченное тело.
        let stranger = SecretKey::generate();
        let fake = Announcement {
            notice: Signed::sign(Notice::Freeze { name: "shop.brand".into(), since: T0 }, &stranger),
            control: Some(Signed::sign(ControlCert { key: stranger.public(), issued_at: T0, expires_at: T0 + DAY }, &stranger)),
        };
        assert!(ok(&w, &b, &[fake], now).is_ok());
        let mut forged = by_control(Notice::Freeze { name: "shop.brand".into(), since: T0 });
        forged.notice.body = Notice::Freeze { name: "other.brand".into(), since: T0 };
        assert!(ok(&w, &b, &[forged], now).is_ok());
    }

    #[test]
    fn json_roundtrip_keeps_signatures() {
        let w = world();
        let b = bundle(&w, true);
        let back: Bundle = from_json(&to_json(&b)).unwrap();
        assert_eq!(ok(&w, &back, &[], T0), ok(&w, &b, &[], T0));
        assert!(ok(&w, &back, &[], T0).is_ok());
    }

    #[test]
    fn newest_picks_highest_seq() {
        let w = world();
        let mut b = bundle(&w, true);
        let old = ok(&w, &b, &[], T0).unwrap();
        b.dns = Signed::sign(DnsRecords { seq: 7, ..b.dns.body }, &w.owner);
        let new = ok(&w, &b, &[], T0).unwrap();
        assert_eq!(newest([new.clone(), old]).unwrap().seq, 7);
    }
}
