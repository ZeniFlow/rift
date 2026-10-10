//! Merkle-дерево по RFC 6962 / RFC 9162 (как в Certificate Transparency).
//! Листья и узлы хэшируются с разными префиксами, поэтому лист нельзя выдать за узел.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash(pub [u8; 32]);

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let bad = || serde::de::Error::custom("хэш: ожидалось 64 hex-символа");
        if s.len() != 64 || !s.is_ascii() {
            return Err(bad());
        }
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
        }
        Ok(Hash(out))
    }
}

pub fn leaf_hash(data: &[u8]) -> Hash {
    Hash(Sha256::new().chain_update([0u8]).chain_update(data).finalize().into())
}

pub fn node_hash(l: &Hash, r: &Hash) -> Hash {
    Hash(Sha256::new().chain_update([1u8]).chain_update(l.0).chain_update(r.0).finalize().into())
}

/// Наибольшая степень двойки строго меньше n (n ≥ 2).
fn split(n: usize) -> usize {
    1 << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// MTH из RFC 6962.
pub fn root_of(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => Hash(Sha256::digest([]).into()),
        1 => leaves[0],
        n => {
            let k = split(n);
            node_hash(&root_of(&leaves[..k]), &root_of(&leaves[k..]))
        }
    }
}

/// Доказательство включения листа `m` в дерево из `leaves` (PATH из RFC 6962). Требует m < n.
pub fn inclusion_path(leaves: &[Hash], m: usize) -> Vec<Hash> {
    let n = leaves.len();
    assert!(m < n);
    if n == 1 {
        return vec![];
    }
    let k = split(n);
    if m < k {
        let mut p = inclusion_path(&leaves[..k], m);
        p.push(root_of(&leaves[k..]));
        p
    } else {
        let mut p = inclusion_path(&leaves[k..], m - k);
        p.push(root_of(&leaves[..k]));
        p
    }
}

/// Доказательство, что дерево из первых `m` листьев — префикс дерева из `leaves` (PROOF). Требует 0 < m ≤ n.
pub fn consistency_proof(leaves: &[Hash], m: usize) -> Vec<Hash> {
    assert!(0 < m && m <= leaves.len());
    subproof(leaves, m, true)
}

fn subproof(leaves: &[Hash], m: usize, complete: bool) -> Vec<Hash> {
    let n = leaves.len();
    if m == n {
        return if complete { vec![] } else { vec![root_of(leaves)] };
    }
    let k = split(n);
    if m <= k {
        let mut p = subproof(&leaves[..k], m, complete);
        p.push(root_of(&leaves[k..]));
        p
    } else {
        let mut p = subproof(&leaves[k..], m - k, false);
        p.push(root_of(&leaves[..k]));
        p
    }
}

/// RFC 9162 §2.1.3.2.
pub fn verify_inclusion(leaf: &Hash, index: u64, size: u64, path: &[Hash], root: &Hash) -> bool {
    if index >= size {
        return false;
    }
    let (mut f, mut s, mut r) = (index, size - 1, *leaf);
    for p in path {
        if s == 0 {
            return false;
        }
        if f & 1 == 1 || f == s {
            r = node_hash(p, &r);
            if f & 1 == 0 {
                while f & 1 == 0 && f != 0 {
                    f >>= 1;
                    s >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        f >>= 1;
        s >>= 1;
    }
    s == 0 && r == *root
}

/// RFC 9162 §2.1.4.2.
pub fn verify_consistency(old: u64, new: u64, old_root: &Hash, new_root: &Hash, proof: &[Hash]) -> bool {
    if old > new {
        return false;
    }
    if old == new {
        return proof.is_empty() && old_root == new_root;
    }
    if old == 0 {
        return proof.is_empty(); // пустое дерево — префикс любого
    }
    let mut c: Vec<Hash> = Vec::with_capacity(proof.len() + 1);
    if old.is_power_of_two() {
        c.push(*old_root);
    }
    c.extend_from_slice(proof);
    if c.is_empty() {
        return false;
    }
    let (mut f, mut s) = (old - 1, new - 1);
    while f & 1 == 1 {
        f >>= 1;
        s >>= 1;
    }
    let (mut fr, mut sr) = (c[0], c[0]);
    for p in &c[1..] {
        if s == 0 {
            return false;
        }
        if f & 1 == 1 || f == s {
            fr = node_hash(p, &fr);
            sr = node_hash(p, &sr);
            if f & 1 == 0 {
                while f & 1 == 0 && f != 0 {
                    f >>= 1;
                    s >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, p);
        }
        f >>= 1;
        s >>= 1;
    }
    s == 0 && fr == *old_root && sr == *new_root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n).map(|i| leaf_hash(format!("entry {i}").as_bytes())).collect()
    }

    #[test]
    fn known_hashes() {
        // SHA-256 от пустой строки и от одного байта 0x00 (лист с пустыми данными): общеизвестные значения.
        assert_eq!(root_of(&[]).to_string(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(leaf_hash(b"").to_string(), "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d");
    }

    #[test]
    fn leaf_cannot_pose_as_node() {
        let l = leaves(2);
        let mut both = l[0].0.to_vec();
        both.extend(l[1].0);
        assert_ne!(leaf_hash(&both), node_hash(&l[0], &l[1]));
    }

    #[test]
    fn inclusion_all_sizes_and_indices() {
        for n in 1..=70 {
            let l = leaves(n);
            let root = root_of(&l);
            for i in 0..n {
                let path = inclusion_path(&l, i);
                assert!(verify_inclusion(&l[i], i as u64, n as u64, &path, &root), "n={n} i={i}");
                // не тот индекс / размер / лист / корень / хвост пути
                // индекс вне дерева
                assert!(!verify_inclusion(&l[i], n as u64, n as u64, &path, &root));
                // корень дерева другого размера (размер и корень связаны подписью головы)
                let longer = leaves(n + 1);
                assert!(!verify_inclusion(&l[i], i as u64, n as u64 + 1, &path, &root_of(&longer)), "n={n} i={i}");
                assert!(!verify_inclusion(&leaf_hash(b"x"), i as u64, n as u64, &path, &root));
                assert!(!verify_inclusion(&l[i], i as u64, n as u64, &path, &leaf_hash(b"r")));
                if !path.is_empty() {
                    assert!(!verify_inclusion(&l[i], i as u64, n as u64, &path[1..], &root));
                    let mut bad = path.clone();
                    bad[0] = leaf_hash(b"bad");
                    assert!(!verify_inclusion(&l[i], i as u64, n as u64, &bad, &root));
                }
            }
        }
    }

    #[test]
    fn consistency_all_sizes() {
        for n in 1..=70 {
            let l = leaves(n);
            let new_root = root_of(&l);
            for m in 1..=n {
                let old_root = root_of(&l[..m]);
                let proof = consistency_proof(&l, m);
                assert!(verify_consistency(m as u64, n as u64, &old_root, &new_root, &proof), "m={m} n={n}");
                if m < n {
                    // переписанная история: другой старый корень или другой новый
                    assert!(!verify_consistency(m as u64, n as u64, &leaf_hash(b"fork"), &new_root, &proof));
                    assert!(!verify_consistency(m as u64, n as u64, &old_root, &leaf_hash(b"fork"), &proof));
                    assert!(!verify_consistency(m as u64, n as u64 + 1, &old_root, &root_of(&leaves(n + 1)), &proof));
                    if let Some((_, rest)) = proof.split_first() {
                        assert!(!verify_consistency(m as u64, n as u64, &old_root, &new_root, rest));
                    }
                }
            }
        }
    }

    #[test]
    fn rewritten_history_is_inconsistent() {
        // Лог «передумал» насчёт записи 3: корни по-прежнему подписаны им, но совместимы быть не могут.
        let a = leaves(8);
        let mut b = a.clone();
        b[3] = leaf_hash(b"rewritten");
        b.push(leaf_hash(b"more"));
        let proof = consistency_proof(&b, 8);
        assert!(!verify_consistency(8, 9, &root_of(&a), &root_of(&b), &proof));
    }

    #[test]
    fn hash_serde_roundtrip() {
        let h = leaf_hash(b"x");
        let j = serde_json::to_string(&h).unwrap();
        assert_eq!(serde_json::from_str::<Hash>(&j).unwrap(), h);
        assert!(serde_json::from_str::<Hash>("\"zz\"").is_err());
    }
}
