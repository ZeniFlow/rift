//! Transparency-логи (trust.md §3). Лог — append-only Merkle-дерево; выпускающий подписывает
//! «голову» (размер + корень + время), свидетели проверяют, что история только дописывается,
//! и подписывают голову тоже. Запись считается выпущенной не позже `head.time`
//! и только если голову подписали достаточно свидетелей.
//!
//! Это защищает от трёх вещей: выпуск задним числом (украденным или просроченным ключом),
//! «раздвоение» истории (разным нодам показывают разное) и тихое переписывание.

use serde::{Deserialize, Serialize};

use crate::merkle::{Hash, consistency_proof, inclusion_path, leaf_hash, root_of, verify_consistency, verify_inclusion};
use crate::{Error, Kind, Logged, PublicKey, SecretKey, Signature, Signed, Time, Trust};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeHead {
    /// Ключ лога: им подписана голова, им же подписаны записи в этом логе.
    pub log: PublicKey,
    pub size: u64,
    pub root: Hash,
    pub time: Time,
}

/// Что подписывает свидетель: та же голова, но под другим «видом» (подпись лога нельзя выдать за свою).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cosign(pub TreeHead);

crate::kinds!(TreeHead => "head", Cosign => "cosign");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cosig {
    pub witness: PublicKey,
    pub sig: Signature,
}

impl Cosig {
    pub fn sign(head: &Signed<TreeHead>, key: &SecretKey) -> Self {
        let msg = Signed::<Cosign>::message(&Cosign(head.body.clone()));
        Self { witness: key.public(), sig: key.sign(&msg) }
    }

    pub fn valid(&self, head: &Signed<TreeHead>) -> bool {
        let msg = Signed::<Cosign>::message(&Cosign(head.body.clone()));
        self.witness.verify(&msg, &self.sig).is_ok()
    }
}

/// Доказательство, что запись есть в логе: путь в дереве + голова, под которой он считается.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    pub index: u64,
    pub path: Vec<Hash>,
    pub head: Signed<TreeHead>,
    pub cosigs: Vec<Cosig>,
}

/// Запись в логе — это полный подписанный сертификат с указанием вида.
pub fn entry_of<T: Kind + Serialize>(s: &Signed<T>) -> String {
    format!("{}\n{}", T::KIND, serde_json::to_string(s).expect("сериализуется"))
}

/// Проверка доказательства. Возвращает `head.time`: запись выпущена НЕ ПОЗЖЕ этого момента.
pub fn check_proof(entry: &str, p: &Proof, log_key: &PublicKey, t: &Trust, what: &'static str) -> Result<Time, Error> {
    let h = &p.head;
    if !h.verify(log_key) || h.body.log != *log_key {
        return Err(Error::BadSignature(what));
    }
    let witnessed = t
        .witnesses
        .iter()
        .filter(|w| p.cosigs.iter().any(|c| c.witness == **w && c.valid(h)))
        .count();
    if witnessed < t.threshold {
        return Err(Error::Log(what, "голову подписали не все нужные свидетели"));
    }
    if !verify_inclusion(&leaf_hash(entry.as_bytes()), p.index, h.body.size, &p.path, &h.body.root) {
        return Err(Error::Log(what, "записи нет в логе"));
    }
    Ok(h.body.time)
}

/// Лог в памяти / файле.
// ponytail: деревья пересчитываются с нуля на каждое доказательство: O(n) на запрос. Хватит до ~10^5 записей.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Log {
    pub entries: Vec<String>,
}

impl Log {
    pub fn len(&self) -> u64 {
        self.entries.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn append(&mut self, entry: String) -> u64 {
        self.entries.push(entry);
        self.len() - 1
    }

    fn hashes(&self, size: usize) -> Vec<Hash> {
        self.entries[..size].iter().map(|e| leaf_hash(e.as_bytes())).collect()
    }

    pub fn head(&self, key: &SecretKey, time: Time) -> Signed<TreeHead> {
        let root = root_of(&self.hashes(self.entries.len()));
        Signed::sign(TreeHead { log: key.public(), size: self.len(), root, time }, key)
    }

    /// Доказательство записи `index` под головой `head` (которую лог когда-то выпустил).
    pub fn prove(&self, index: u64, head: &Signed<TreeHead>, cosigs: Vec<Cosig>) -> Option<Proof> {
        let size = head.body.size as usize;
        if size > self.entries.len() || index >= head.body.size {
            return None;
        }
        let leaves = self.hashes(size);
        if root_of(&leaves) != head.body.root {
            return None; // лог не тот или переписан
        }
        Some(Proof { index, path: inclusion_path(&leaves, index as usize), head: head.clone(), cosigs })
    }

    pub fn consistency(&self, old: u64, new: u64) -> Option<Vec<Hash>> {
        let (old, new) = (old as usize, new as usize);
        (0 < old && old <= new && new <= self.entries.len()).then(|| consistency_proof(&self.hashes(new), old))
    }
}

/// Последняя голова каждого лога, которую видел свидетель.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Witness {
    pub seen: Vec<Seen>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Seen {
    pub log: PublicKey,
    pub size: u64,
    pub root: Hash,
    pub time: Time,
}

/// Допустимый уход часов лога вперёд: голова «из будущего» позволила бы выдать сертификат раньше времени.
const SKEW: Time = 300;

impl Witness {
    /// Подписывает голову, только если она честно продолжает то, что свидетель уже видел.
    /// `consistency` — доказательство от последней виденной головы до этой (нужно, если лог уже известен).
    pub fn cosign(&mut self, key: &SecretKey, head: &Signed<TreeHead>, consistency: &[Hash], now: Time) -> Result<Cosig, Error> {
        let h = &head.body;
        if !head.verify(&h.log) {
            return Err(Error::BadSignature("голова не подписана логом"));
        }
        if h.time > now + SKEW {
            return Err(Error::Log("голова", "время из будущего"));
        }
        match self.seen.iter_mut().find(|s| s.log == h.log) {
            Some(s) => {
                if h.size < s.size || h.time < s.time {
                    return Err(Error::Log("голова", "лог откатился назад"));
                }
                if h.size == s.size {
                    if h.root != s.root {
                        return Err(Error::Log("голова", "тот же размер, другой корень: раздвоение истории"));
                    }
                } else if !verify_consistency(s.size, h.size, &s.root, &h.root, consistency) {
                    return Err(Error::Log("голова", "история переписана: нет доказательства согласованности"));
                }
                (s.size, s.root, s.time) = (h.size, h.root, h.time);
            }
            None => self.seen.push(Seen { log: h.log, size: h.size, root: h.root, time: h.time }),
        }
        Ok(Cosig::sign(head, key))
    }

    pub fn size_of(&self, log: &PublicKey) -> u64 {
        self.seen.iter().find(|s| s.log == *log).map_or(0, |s| s.size)
    }
}

/// ТОЛЬКО ДЛЯ ТЕСТОВ И РАЗРАБОТКИ: кладёт сертификат в новый лог из одной записи, подписывает голову
/// временем `at` и просит `witnesses` подписать её. Настоящий лог живёт долго и растёт (см. `Log`).
pub fn logged_now<T: Kind + Serialize>(log_key: &SecretKey, cert: Signed<T>, at: Time, witnesses: &[&SecretKey]) -> Logged<T> {
    let mut log = Log::default();
    let index = log.append(entry_of(&cert));
    let head = log.head(log_key, at);
    let cosigs = witnesses.iter().map(|k| Cosig::sign(&head, k)).collect();
    Logged { proof: log.prove(index, &head, cosigs).expect("голова только что подписана"), cert }
}
