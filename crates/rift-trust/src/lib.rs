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

pub mod log;
pub mod merkle;

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

impl Announcement {
    /// Относится ли объявление к этой цепочке. Резолвер отдаёт клиенту только такие: компактно и без утечки чужого.
    pub fn concerns(&self, b: &Bundle, root: &PublicKey) -> bool {
        match &self.notice.body {
            Notice::Freeze { name, .. } => *name == b.domain.cert.body.name,
            Notice::RevokeZone { zone, .. } => *zone == b.zone.cert.body.zone,
            Notice::RevokeKey { key, .. } => {
                key == root
                    || *key == b.control.body.key
                    || *key == b.zone.cert.body.owner
                    || *key == b.domain.cert.body.owner
                    || b.registrar.as_ref().is_some_and(|r| r.cert.body.registrar == *key)
            }
        }
    }
}

// ---------------------------------------------------------------- подписи

pub trait Kind {
    const KIND: &'static str;
}
#[macro_export]
macro_rules! kinds { ($($t:ty => $k:literal),*) => {$(impl $crate::Kind for $t { const KIND: &'static str = $k; })*} }
kinds!(ControlCert => "control", ZoneCert => "zone", RegistrarCert => "registrar",
       DomainRecord => "domain", DnsRecords => "dns", Notice => "notice");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signed<T> {
    pub body: T,
    pub sig: Signature,
}

impl<T: Kind + Serialize> Signed<T> {
    pub(crate) fn message(body: &T) -> Vec<u8> {
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

/// Кому верит проверяющий. Вшивается в клиент.
#[derive(Debug, Clone)]
pub struct Trust {
    pub root: PublicKey,
    /// Свидетели, чьи подписи на головах логов считаются.
    pub witnesses: Vec<PublicKey>,
    /// Сколько разных свидетелей должны подписать голову. 0 отключает защиту от задним числом и раздвоения: только для отладки.
    pub threshold: usize,
}

/// Сертификат + доказательство, что он записан в логе выпустившего.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Logged<T> {
    pub cert: Signed<T>,
    pub proof: log::Proof,
}

/// Всё, что хост показывает клиенту (как цепочка сертификатов в TLS).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    /// Выдан root, который оффлайн: не логируется.
    pub control: Signed<ControlCert>,
    /// В логе control.
    pub zone: Logged<ZoneCert>,
    /// В логе владельца зоны. Нет, если домен зарегистрировал сам владелец зоны.
    pub registrar: Option<Logged<RegistrarCert>>,
    /// В логе владельца зоны (он же секвенсор: trust.md §2).
    pub domain: Logged<DomainRecord>,
    /// Не логируется: меняется часто, подписывает владелец домена.
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
    /// Проблема с логом: нет записи, нет подписей свидетелей, история переписана.
    Log(&'static str, &'static str),
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
            Error::Log(w, why) => write!(f, "лог ({w}): {why}"),
        }
    }
}
impl std::error::Error for Error {}

type R<T> = Result<T, Error>;

fn within(t: Time, from: Time, to: Time) -> bool {
    from <= t && t <= to
}

/// Сертификат выпущен корректно: заявленное время в окне родителя и не позже головы лога,
/// а сама запись попала в лог до конца срока родителя (иначе её мог дописать «мёртвый» родитель).
fn issued_ok(claimed: Time, logged_by: Time, parent_from: Time, parent_to: Time) -> bool {
    parent_from <= claimed && claimed <= logged_by && logged_by <= parent_to
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

/// Полная проверка. `trust` вшит в клиент. `notices` — всё, что известно об отзывах;
/// объявления с неверной подписью молча игнорируются (мусор не должен ломать резолв).
pub fn verify(trust: &Trust, b: &Bundle, notices: &[Announcement], now: Time) -> R<Resolved> {
    let root = &trust.root;
    let (control, zone, dom, dns) = (&b.control.body, &b.zone.cert.body, &b.domain.cert.body, &b.dns.body);

    // 1. подписи по цепочке
    if !b.control.verify(root) {
        return Err(Error::BadSignature("control (не root)"));
    }
    if !b.zone.cert.verify(&control.key) {
        return Err(Error::BadSignature("зона (не control)"));
    }
    let domain_signer = match &b.registrar {
        Some(r) => {
            if !r.cert.verify(&zone.owner) {
                return Err(Error::BadSignature("регистратор (не владелец зоны)"));
            }
            if r.cert.body.zone != zone.zone {
                return Err(Error::Mismatch("зона регистратора"));
            }
            r.cert.body.registrar
        }
        None => zone.owner,
    };
    if !b.domain.cert.verify(&domain_signer) {
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

    // 3. логи: запись есть, голову подписали свидетели. Время выпуска — верхняя граница, а не слово выпускающего.
    use log::{check_proof, entry_of};
    let tz = check_proof(&entry_of(&b.zone.cert), &b.zone.proof, &control.key, trust, "зона")?;
    let tr = b
        .registrar
        .as_ref()
        .map(|r| check_proof(&entry_of(&r.cert), &r.proof, &zone.owner, trust, "регистратор"))
        .transpose()?;
    let td = check_proof(&entry_of(&b.domain.cert), &b.domain.proof, &zone.owner, trust, "домен")?;

    // 4. вложенность окон
    if !issued_ok(zone.issued_at, tz, control.issued_at, control.expires_at) {
        return Err(Error::OutsideParentWindow("зона"));
    }
    let domain_parent = match (&b.registrar, tr) {
        (Some(r), Some(tr)) => {
            if !issued_ok(r.cert.body.issued_at, tr, zone.issued_at, zone.expires_at) {
                return Err(Error::OutsideParentWindow("регистратор"));
            }
            (r.cert.body.issued_at, r.cert.body.expires_at)
        }
        _ => (zone.issued_at, zone.expires_at),
    };
    if !issued_ok(dom.issued_at, td, domain_parent.0, domain_parent.1) {
        return Err(Error::OutsideParentWindow("домен"));
    }
    // Записи не логируются: окно по заявленному времени (подделать его может только сам владелец домена).
    if !within(dns.issued_at, dom.issued_at, dom.expires_at) {
        return Err(Error::OutsideParentWindow("записи"));
    }

    // 5. сроки сейчас. Control не проверяем: его срок — окно выпуска (trust.md §4).
    live("зона", zone.issued_at, zone.expires_at, now)?;
    if let Some(r) = &b.registrar {
        live("регистратор", r.cert.body.issued_at, r.cert.body.expires_at, now)?;
    }
    live("домен", dom.issued_at, dom.expires_at, now)?;
    live("записи", dns.issued_at, dns.expires_at, now)?;

    // 6. объявления: подписаны root или любым control, которого признаёт root
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
                // Сертификат пережил отзыв ключа, только если ДОКАЗАНО (головой лога), что он выпущен до `since`.
                let hit = |signer: &PublicKey, logged_by: Time, what| {
                    (signer == key && logged_by >= *since).then_some(Error::Revoked(what))
                };
                let found = hit(root, control.issued_at, "root")
                    .or_else(|| hit(&control.key, tz, "ключ control"))
                    .or_else(|| hit(&zone.owner, tr.unwrap_or(td), "ключ владельца зоны"))
                    .or_else(|| b.registrar.as_ref().and_then(|r| hit(&r.cert.body.registrar, td, "ключ регистратора")))
                    // записи без лога: можно опираться только на заявленное время
                    .or_else(|| hit(&dom.owner, dns.issued_at, "ключ владельца домена"));
                if let Some(e) = found {
                    return Err(e);
                }
            }
            _ => {}
        }
    }

    let valid_until = [Some(zone.expires_at), b.registrar.as_ref().map(|r| r.cert.body.expires_at), Some(dom.expires_at), Some(dns.expires_at)]
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
    use crate::log::{Cosig, Log, Witness, entry_of};
    use crate::merkle::Hash;

    const DAY: Time = 86_400;
    const T0: Time = 1_000_000;

    struct World {
        root: SecretKey,
        control: SecretKey,
        zone_owner: SecretKey,
        registrar: SecretKey,
        owner: SecretKey,
        host: SecretKey,
        witnesses: [SecretKey; 2],
    }

    fn world() -> World {
        let k = SecretKey::generate;
        World { root: k(), control: k(), zone_owner: k(), registrar: k(), owner: k(), host: k(), witnesses: [k(), k()] }
    }

    fn trust(w: &World, threshold: usize) -> Trust {
        Trust { root: w.root.public(), witnesses: w.witnesses.iter().map(|k| k.public()).collect(), threshold }
    }

    /// Параметры фикстуры. Control всегда выпущен в T0 на 90 дней.
    #[derive(Clone)]
    struct Opt {
        via_registrar: bool,
        zone_issued: Time,
        zone_logged: Time,
        zone_exp: Time,
        reg_logged: Time,
        dom_issued: Time,
        dom_logged: Time,
        dom_exp: Time,
        dns_issued: Time,
        dns_exp: Time,
        seq: u64,
    }

    impl Default for Opt {
        fn default() -> Self {
            Opt {
                via_registrar: true,
                zone_issued: T0,
                zone_logged: T0,
                zone_exp: T0 + 730 * DAY,
                reg_logged: T0,
                dom_issued: T0,
                dom_logged: T0,
                dom_exp: T0 + 365 * DAY,
                dns_issued: T0,
                dns_exp: T0 + 30 * DAY,
                seq: 1,
            }
        }
    }

    /// Кладёт сертификат в лог (среди посторонних записей), подписывает голову временем `at`,
    /// просит всех свидетелей подписать её.
    fn logged<T: Kind + Serialize>(log_key: &SecretKey, cert: Signed<T>, at: Time, w: &World) -> Logged<T> {
        let mut log = Log::default();
        for i in 0..5 {
            log.append(format!("noise {i}"));
        }
        let index = log.append(entry_of(&cert));
        log.append("noise after".into());
        let head = log.head(log_key, at);
        let cosigs = w.witnesses.iter().map(|k| Cosig::sign(&head, k)).collect();
        Logged { proof: log.prove(index, &head, cosigs).unwrap(), cert }
    }

    fn build(w: &World, o: &Opt) -> Bundle {
        let control = Signed::sign(ControlCert { key: w.control.public(), issued_at: T0, expires_at: T0 + 90 * DAY }, &w.root);
        let zone = Signed::sign(
            ZoneCert { zone: "brand".into(), owner: w.zone_owner.public(), issued_at: o.zone_issued, expires_at: o.zone_exp },
            &w.control,
        );
        let zone = logged(&w.control, zone, o.zone_logged, w);
        let registrar = o.via_registrar.then(|| {
            let c = Signed::sign(
                RegistrarCert { zone: "brand".into(), registrar: w.registrar.public(), issued_at: T0, expires_at: T0 + 365 * DAY },
                &w.zone_owner,
            );
            logged(&w.zone_owner, c, o.reg_logged, w)
        });
        let signer = if o.via_registrar { &w.registrar } else { &w.zone_owner };
        let domain = Signed::sign(
            DomainRecord { name: "shop.brand".into(), owner: w.owner.public(), issued_at: o.dom_issued, expires_at: o.dom_exp },
            signer,
        );
        let domain = logged(&w.zone_owner, domain, o.dom_logged, w);
        let dns = Signed::sign(
            DnsRecords {
                name: "shop.brand".into(),
                seq: o.seq,
                records: vec![Record::Host(w.host.public()), Record::Txt("hi".into())],
                issued_at: o.dns_issued,
                expires_at: o.dns_exp,
            },
            &w.owner,
        );
        Bundle { control, zone, registrar, domain, dns }
    }

    fn ok(w: &World, b: &Bundle, n: &[Announcement], now: Time) -> Result<Resolved, Error> {
        verify(&trust(w, 2), b, n, now)
    }

    fn bad_log(r: Result<Resolved, Error>) -> bool {
        matches!(r, Err(Error::Log(..)))
    }

    #[test]
    fn resolves_via_registrar_and_directly_from_zone_owner() {
        let w = world();
        for via_registrar in [true, false] {
            let r = ok(&w, &build(&w, &Opt { via_registrar, ..Default::default() }), &[], T0 + DAY).unwrap();
            assert_eq!(r.name, "shop.brand");
            assert_eq!(r.hosts, vec![w.host.public()]);
            assert_eq!(r.txt, vec!["hi".to_string()]);
            assert_eq!(r.owner, w.owner.public());
            assert_eq!(r.valid_until, T0 + 30 * DAY);
        }
    }

    #[test]
    fn control_may_be_long_dead() {
        // Control-сертификат истёк 90 дней назад — домен всё равно резолвится.
        let w = world();
        let b = build(&w, &Opt { dns_exp: T0 + 300 * DAY, ..Default::default() });
        assert!(ok(&w, &b, &[], T0 + 200 * DAY).is_ok());
    }

    #[test]
    fn wrong_root_or_any_wrong_signer_is_rejected() {
        let w = world();
        let b = build(&w, &Opt::default());
        let mut other = trust(&w, 2);
        other.root = SecretKey::generate().public();
        assert!(matches!(verify(&other, &b, &[], T0), Err(Error::BadSignature(_))));

        let stranger = SecretKey::generate();
        let mut x = b.clone();
        x.control = Signed::sign(x.control.body.clone(), &stranger);
        assert!(matches!(ok(&w, &x, &[], T0), Err(Error::BadSignature(_))));
        let mut x = b.clone();
        x.zone.cert = Signed::sign(x.zone.cert.body.clone(), &stranger);
        assert!(matches!(ok(&w, &x, &[], T0), Err(Error::BadSignature(_))));
        let mut x = b.clone();
        let r = x.registrar.as_mut().unwrap();
        r.cert = Signed::sign(r.cert.body.clone(), &stranger);
        assert!(matches!(ok(&w, &x, &[], T0), Err(Error::BadSignature(_))));
        let mut x = b.clone();
        x.domain.cert = Signed::sign(x.domain.cert.body.clone(), &stranger);
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
        let mut b = build(&w, &Opt::default());
        b.dns.body.records = vec![Record::Host(SecretKey::generate().public())];
        assert!(matches!(ok(&w, &b, &[], T0), Err(Error::BadSignature(_))));
        let mut b = build(&w, &Opt::default());
        b.zone.cert.body.owner = SecretKey::generate().public();
        assert!(matches!(ok(&w, &b, &[], T0), Err(Error::BadSignature(_))));
    }

    #[test]
    fn registrar_cannot_sell_outside_its_zone_or_without_cert() {
        let w = world();
        // Регистратор зоны `other` продаёт имя в `brand`.
        let mut b = build(&w, &Opt::default());
        let r = b.registrar.as_mut().unwrap();
        r.cert = Signed::sign(RegistrarCert { zone: "other".into(), ..r.cert.body.clone() }, &w.zone_owner);
        assert!(matches!(ok(&w, &b, &[], T0), Err(Error::Mismatch(_))));
        // Домен вне зоны.
        let mut b = build(&w, &Opt { via_registrar: false, ..Default::default() });
        b.domain.cert = Signed::sign(DomainRecord { name: "shop.evil".into(), ..b.domain.cert.body.clone() }, &w.zone_owner);
        b.dns = Signed::sign(DnsRecords { name: "shop.evil".into(), ..b.dns.body.clone() }, &w.owner);
        assert!(matches!(ok(&w, &b, &[], T0), Err(Error::Mismatch(_))));
        // Регистратор без сертификата: подпись не сойдётся с владельцем зоны.
        let mut b = build(&w, &Opt::default());
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
        let b = build(&w, &Opt::default());
        assert!(matches!(ok(&w, &b, &[], T0 - 1), Err(Error::NotYetValid(_))));
        assert!(matches!(ok(&w, &b, &[], T0 + 30 * DAY), Err(Error::Expired("записи"))));

        // Домен живёт не дольше зоны.
        let b = build(&w, &Opt { via_registrar: false, zone_exp: T0 + 10 * DAY, ..Default::default() });
        assert!(matches!(ok(&w, &b, &[], T0 + 11 * DAY), Err(Error::Expired("зона"))));

        // Записи выпущены раньше домена.
        let b = build(&w, &Opt { dns_issued: T0 - 1, ..Default::default() });
        assert!(matches!(ok(&w, &b, &[], T0), Err(Error::OutsideParentWindow("записи"))));
    }

    #[test]
    fn backdating_by_expired_control_is_caught_by_the_log() {
        // Ключ control утёк / control давно просрочен (окно до T0+90). Злоумышленник подписывает зону
        // с заявленным временем внутри окна, но записать её в лог может только сейчас.
        let w = world();
        let backdated = Opt { zone_issued: T0 + DAY, zone_logged: T0 + 91 * DAY, ..Default::default() };
        let b = build(&w, &backdated);
        assert!(matches!(ok(&w, &b, &[], T0 + 92 * DAY), Err(Error::OutsideParentWindow("зона"))));
        // Честная зона, попавшая в лог внутри окна, остаётся действительной и после смерти control.
        let honest = Opt {
            via_registrar: false,
            zone_issued: T0 + DAY,
            zone_logged: T0 + 2 * DAY,
            dom_issued: T0 + 3 * DAY,
            dom_logged: T0 + 3 * DAY,
            dns_issued: T0 + 3 * DAY,
            dns_exp: T0 + 200 * DAY,
            ..Default::default()
        };
        assert!(ok(&w, &build(&w, &honest), &[], T0 + 150 * DAY).is_ok());
        // Заявленное время позже головы — выпускающий приписал себе «будущее».
        let future = Opt { zone_issued: T0 + 5 * DAY, zone_logged: T0 + DAY, ..Default::default() };
        assert!(matches!(ok(&w, &build(&w, &future), &[], T0 + 6 * DAY), Err(Error::OutsideParentWindow("зона"))));
        // То же для домена и регистратора (лог владельца зоны).
        let dom = Opt { dom_logged: T0 + 400 * DAY, ..Default::default() };
        assert!(matches!(ok(&w, &build(&w, &dom), &[], T0 + 5 * DAY), Err(Error::OutsideParentWindow("домен"))));
    }

    #[test]
    fn revocation_survives_only_with_proof_of_early_issuance() {
        let w = world();
        let revoke = |since| Announcement {
            notice: Signed::sign(Notice::RevokeKey { key: w.zone_owner.public(), since }, &w.control),
            control: Some(build(&w, &Opt::default()).control),
        };
        let now = T0 + 25 * DAY;
        // Ключ владельца зоны украден с T0+10. Домен записан в лог на T0+5 — доказано, что до кражи.
        let early = build(&w, &Opt { via_registrar: false, dom_logged: T0 + 5 * DAY, ..Default::default() });
        assert!(ok(&w, &early, &[revoke(T0 + 10 * DAY)], now).is_ok());
        // Вор подписал домен «T0» (задним числом), но в лог он попал на T0+20: после отзыва — недействителен.
        let late = build(&w, &Opt { via_registrar: false, dom_logged: T0 + 20 * DAY, ..Default::default() });
        assert!(matches!(ok(&w, &late, &[revoke(T0 + 10 * DAY)], now), Err(Error::Revoked(_))));
    }

    #[test]
    fn log_proofs_are_checked() {
        let w = world();
        let b = build(&w, &Opt::default());
        let t = |th| trust(&w, th);

        // Достаточно ли свидетелей.
        let mut x = b.clone();
        x.zone.proof.cosigs.truncate(1);
        assert!(bad_log(verify(&t(2), &x, &[], T0)));
        assert!(verify(&t(1), &x, &[], T0).is_ok());
        // Один свидетель, подписавший дважды, считается один раз.
        let mut x = b.clone();
        x.zone.proof.cosigs = vec![x.zone.proof.cosigs[0].clone(), x.zone.proof.cosigs[0].clone()];
        assert!(bad_log(verify(&t(2), &x, &[], T0)));
        // Подпись постороннего «свидетеля» не считается.
        let mut x = b.clone();
        let fake = SecretKey::generate();
        x.zone.proof.cosigs = vec![Cosig::sign(&x.zone.proof.head, &fake), Cosig::sign(&x.zone.proof.head, &fake)];
        assert!(bad_log(verify(&t(2), &x, &[], T0)));
        // Подпись свидетеля с другой головы (replay).
        let mut x = b.clone();
        x.zone.proof.cosigs = b.domain.proof.cosigs.clone();
        assert!(bad_log(verify(&t(2), &x, &[], T0)));
        // Подпись лога выдана не тем ключом (голова подписана владельцем зоны, а зона — в логе control).
        let mut x = b.clone();
        x.zone.proof = b.domain.proof.clone();
        assert!(matches!(verify(&t(2), &x, &[], T0), Err(Error::BadSignature(_))));
        // Доказательство от другой записи.
        let mut x = b.clone();
        x.domain.proof = b.registrar.as_ref().unwrap().proof.clone();
        assert!(bad_log(verify(&t(2), &x, &[], T0)));
        // Испорченный путь.
        let mut x = b.clone();
        x.domain.proof.path[0] = crate::merkle::leaf_hash(b"x");
        assert!(bad_log(verify(&t(2), &x, &[], T0)));
        // Порог 0: свидетели не нужны (режим отладки), но включение в лог всё равно проверяется.
        let mut x = b.clone();
        x.zone.proof.cosigs.clear();
        assert!(verify(&t(0), &x, &[], T0).is_ok());
        x.domain.proof.path[0] = crate::merkle::leaf_hash(b"x");
        assert!(bad_log(verify(&t(0), &x, &[], T0)));
    }

    #[test]
    fn notices() {
        let w = world();
        let b = build(&w, &Opt::default());
        let now = T0 + 5 * DAY;
        let by_control = |n| Announcement { notice: Signed::sign(n, &w.control), control: Some(b.control.clone()) };

        // Freeze / RevokeZone
        let freeze = by_control(Notice::Freeze { name: "shop.brand".into(), since: T0 + DAY });
        assert!(matches!(ok(&w, &b, &[freeze.clone()], now), Err(Error::Frozen(_))));
        assert!(ok(&w, &b, &[freeze], T0).is_ok()); // ещё не заморожен
        let rz = by_control(Notice::RevokeZone { zone: "brand".into(), since: T0 });
        assert!(matches!(ok(&w, &b, &[rz], now), Err(Error::Revoked(_))));

        // Украден ключ владельца зоны: регистратор, записанный с `since`, недействителен; до `since` — ок.
        let leak = |since| by_control(Notice::RevokeKey { key: w.zone_owner.public(), since });
        assert!(matches!(ok(&w, &b, &[leak(T0)], now), Err(Error::Revoked(_))));
        assert!(ok(&w, &b, &[leak(T0 + 1)], now).is_ok());
        // Украден ключ control: root отзывает его, зона записана после since → недействительна.
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
    fn json_roundtrip_keeps_signatures_and_proofs() {
        let w = world();
        let b = build(&w, &Opt::default());
        let back: Bundle = from_json(&to_json(&b)).unwrap();
        assert!(ok(&w, &back, &[], T0).is_ok());
    }

    #[test]
    fn newest_picks_highest_seq() {
        let w = world();
        let old = ok(&w, &build(&w, &Opt::default()), &[], T0).unwrap();
        let new = ok(&w, &build(&w, &Opt { seq: 7, ..Default::default() }), &[], T0).unwrap();
        assert_eq!(newest([new, old]).unwrap().seq, 7);
    }

    // ------------------------------------------------------------ свидетель

    fn grow(log: &mut Log, from: usize, to: usize) {
        for i in from..to {
            log.append(format!("entry {i}"));
        }
    }

    #[test]
    fn witness_cosigns_honest_growth_and_refuses_rewrites() {
        let (log_key, wk) = (SecretKey::generate(), SecretKey::generate());
        let mut wit = Witness::default();
        let mut log = Log::default();
        grow(&mut log, 0, 5);
        let h5 = log.head(&log_key, 1000);

        // Первая голова — без доказательств; подпись свидетеля валидна.
        let c = wit.cosign(&wk, &h5, &[], 1000).unwrap();
        assert!(c.valid(&h5) && c.witness == wk.public());
        assert_eq!(wit.size_of(&log_key.public()), 5);
        // Повтор той же головы — можно.
        assert!(wit.cosign(&wk, &h5, &[], 1001).is_ok());

        // Честный рост требует доказательства согласованности.
        grow(&mut log, 5, 9);
        let h9 = log.head(&log_key, 1100);
        assert!(wit.cosign(&wk, &h9, &[], 1100).is_err(), "без доказательства нельзя");
        let proof = log.consistency(5, 9).unwrap();
        assert!(wit.cosign(&wk, &h9, &proof, 1100).is_ok());
        assert_eq!(wit.size_of(&log_key.public()), 9);

        // Раздвоение: тот же размер, другой корень.
        let mut fork = log.clone();
        fork.entries[4] = "evil".into();
        let hf = fork.head(&log_key, 1100);
        assert_eq!(hf.body.size, 9);
        assert!(wit.cosign(&wk, &hf, &[], 1100).is_err());

        // Переписанная история: размер больше, но запись №2 другая.
        let mut rewritten = fork.clone();
        rewritten.entries[2] = "rewritten".into();
        grow(&mut rewritten, 9, 12);
        let hr = rewritten.head(&log_key, 1200);
        let bogus = rewritten.consistency(9, 12).unwrap();
        assert!(wit.cosign(&wk, &hr, &bogus, 1200).is_err());
        assert_eq!(wit.size_of(&log_key.public()), 9, "состояние не должно меняться после отказа");

        // Откат назад по размеру и по времени.
        let mut short = Log::default();
        grow(&mut short, 0, 3);
        assert!(wit.cosign(&wk, &short.head(&log_key, 1300), &[], 1300).is_err());
        grow(&mut log, 9, 10);
        let early = log.head(&log_key, 900);
        assert!(wit.cosign(&wk, &early, &log.consistency(9, 10).unwrap(), 1300).is_err());

        // Время из будущего (лог пытается «зарезервировать» дату) и подпись не логом.
        let future = log.head(&log_key, 1300 + 10_000);
        assert!(wit.cosign(&wk, &future, &log.consistency(9, 10).unwrap(), 1300).is_err());
        let stolen = Signed::sign(h9.body.clone(), &SecretKey::generate());
        assert!(wit.cosign(&wk, &stolen, &[], 1300).is_err());
    }

    #[test]
    fn witness_state_survives_json() {
        let (log_key, wk) = (SecretKey::generate(), SecretKey::generate());
        let mut log = Log::default();
        grow(&mut log, 0, 4);
        let mut wit = Witness::default();
        wit.cosign(&wk, &log.head(&log_key, 10), &[], 10).unwrap();
        let mut back: Witness = from_json(&to_json(&wit)).unwrap();
        assert_eq!(back.size_of(&log_key.public()), 4);
        grow(&mut log, 4, 6);
        let p = log.consistency(4, 6).unwrap();
        assert!(back.cosign(&wk, &log.head(&log_key, 20), &p, 20).is_ok());
    }

    #[allow(dead_code)]
    fn _hash_type_is_used(_: Hash) {}
}
