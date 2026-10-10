//! Хранилище ключа: один файл `wallet.json`. Внутри 24 слова TON, зашифрованные паролем (Argon2id → ChaCha20-Poly1305).
//! Адрес и сеть лежат открыто, чтобы показывать баланс без пароля; они же входят в аутентифицируемые данные шифра,
//! поэтому подменить адрес в файле нельзя: расшифровка не пройдёт.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::{Aead, Payload}};
use serde::{Deserialize, Serialize};
use tonlib_core::{
    TonAddress,
    wallet::{mnemonic::{KeyPair, Mnemonic, WORDLIST_EN_SET}, wallet_version::WalletVersion},
};

use crate::wallet::Wallet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub fn is_testnet(self) -> bool {
        self == Network::Testnet
    }
    /// Публичный API сети по умолчанию.
    pub fn api_url(self) -> &'static str {
        match self {
            Network::Mainnet => "https://toncenter.com/api/v2",
            Network::Testnet => "https://testnet.toncenter.com/api/v2",
        }
    }
}

/// Версия контракта кошелька. V4R2 понимают все кошельки и обозреватели.
pub const VERSION: WalletVersion = WalletVersion::V4R2;

/// Стоимость ключа из пароля. Файл помнит свои параметры, поэтому их можно усиливать, не ломая старые кошельки.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Kdf {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Kdf {
    /// 64 МиБ, 3 прохода: около четверти секунды на обычном ноутбуке.
    pub const STRONG: Kdf = Kdf { m_kib: 64 * 1024, t: 3, p: 1 };
    /// Только для тестов.
    pub const FAST: Kdf = Kdf { m_kib: 8, t: 1, p: 1 };

    fn derive(&self, pass: &str, salt: &[u8]) -> Result<[u8; 32]> {
        let params = Params::new(self.m_kib, self.t, self.p, Some(32)).map_err(|e| anyhow::anyhow!("параметры KDF: {e}"))?;
        let mut key = [0u8; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(pass.as_bytes(), salt, &mut key).map_err(|e| anyhow::anyhow!("KDF: {e}"))?;
        Ok(key)
    }
}

#[derive(Serialize, Deserialize)]
struct File {
    v: u8,
    network: Network,
    address: String,
    kdf: Kdf,
    salt: String,
    nonce: String,
    ct: String,
}

/// Открытые сведения о кошельке.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Info {
    pub network: Network,
    /// Адрес в виде для людей (UQ… / 0Q…: не возвращаемый, на него безопасно слать и на ещё не созданный кошелёк).
    pub address: String,
}

pub struct Vault {
    path: PathBuf,
    kdf: Kdf,
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|e| anyhow::anyhow!("нет случайных чисел: {e}"))?;
    Ok(b)
}

/// 24 слова TON из системного источника случайности. Допустимой считается лишь часть наборов (1 из 256), поэтому перебор.
pub fn generate_words() -> Result<Vec<String>> {
    let mut list: Vec<(&&str, &usize)> = WORDLIST_EN_SET.iter().collect();
    list.sort_by_key(|(_, i)| **i);
    ensure!(list.len() == 2048, "словарь повреждён");
    loop {
        let bytes: [u8; 48] = random()?;
        let words: Vec<&str> = bytes.chunks(2).map(|c| *list[(u16::from_le_bytes([c[0], c[1]]) & 0x7ff) as usize].0).collect();
        if Mnemonic::new(words.clone(), &None).is_ok() {
            return Ok(words.into_iter().map(String::from).collect());
        }
    }
}

fn key_pair(words: &str) -> Result<KeyPair> {
    Mnemonic::from_str(words, &None).map_err(|e| anyhow::anyhow!("секретная фраза не подходит: {e}"))?.to_key_pair().map_err(|e| anyhow::anyhow!("{e}"))
}

fn address_of(kp: &KeyPair) -> Result<TonAddress> {
    Ok(tonlib_core::wallet::ton_wallet::TonWallet::new(VERSION, kp.clone()).map_err(|e| anyhow::anyhow!("{e}"))?.address)
}

impl Vault {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into(), kdf: Kdf::STRONG }
    }

    pub fn with_kdf(mut self, kdf: Kdf) -> Self {
        self.kdf = kdf;
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Новый кошелёк. Возвращает слова: показать пользователю надо сразу, потом их можно получить только с паролем.
    pub fn create(&self, pass: &str, network: Network) -> Result<Vec<String>> {
        let words = generate_words()?;
        self.store(&words.join(" "), pass, network)?;
        Ok(words)
    }

    /// Кошелёк из имеющихся 24 слов.
    pub fn import(&self, words: &str, pass: &str, network: Network) -> Result<()> {
        self.store(&words.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase(), pass, network)
    }

    fn store(&self, words: &str, pass: &str, network: Network) -> Result<()> {
        ensure!(!self.exists(), "кошелёк уже есть: {}", self.path.display());
        ensure!(pass.chars().count() >= 8, "пароль короче 8 знаков");
        let address = address_of(&key_pair(words)?)?.to_base64_url_flags(true, network.is_testnet());
        let (salt, nonce): ([u8; 16], [u8; 12]) = (random()?, random()?);
        let key = self.kdf.derive(pass, &salt)?;
        let ct = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .encrypt((&nonce).into(), Payload { msg: words.as_bytes(), aad: Self::aad(network, &address).as_bytes() })
            .map_err(|_| anyhow::anyhow!("шифрование не удалось"))?;
        let file = File { v: 1, network, address, kdf: self.kdf, salt: B64.encode(salt), nonce: B64.encode(nonce), ct: B64.encode(ct) };
        if let Some(d) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(d)?;
        }
        let tmp = self.path.with_extension("tmp");
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        std::fs::remove_file(&tmp).ok();
        std::io::Write::write_all(&mut o.open(&tmp)?, &serde_json::to_vec_pretty(&file)?)?;
        std::fs::rename(&tmp, &self.path).context("не удалось записать кошелёк")
    }

    fn aad(network: Network, address: &str) -> String {
        format!("rift-wallet/v1|{network:?}|{address}")
    }

    fn read(&self) -> Result<File> {
        let f: File = serde_json::from_slice(&std::fs::read(&self.path).with_context(|| format!("нет кошелька: {}", self.path.display()))?).context("файл кошелька повреждён")?;
        ensure!(f.v == 1, "версия файла кошелька {} не поддерживается", f.v);
        Ok(f)
    }

    /// Адрес и сеть без пароля.
    pub fn info(&self) -> Result<Info> {
        let f = self.read()?;
        Ok(Info { network: f.network, address: f.address })
    }

    /// Расшифровывает слова. Неверный пароль, чужой адрес в файле и порча одинаково дают отказ.
    pub fn reveal(&self, pass: &str) -> Result<Vec<String>> {
        let f = self.read()?;
        let (salt, nonce, ct) = (B64.decode(&f.salt)?, B64.decode(&f.nonce)?, B64.decode(&f.ct)?);
        let nonce: [u8; 12] = nonce.try_into().map_err(|_| anyhow::anyhow!("файл кошелька повреждён"))?;
        ensure!(salt.len() >= 8, "файл кошелька повреждён");
        ensure!(f.kdf.m_kib >= 8 && f.kdf.m_kib <= 1 << 20 && f.kdf.t >= 1 && f.kdf.t <= 20 && f.kdf.p >= 1 && f.kdf.p <= 16, "параметры KDF в файле недопустимы");
        let key = f.kdf.derive(pass, &salt)?;
        let plain = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .decrypt((&nonce).into(), Payload { msg: &ct, aad: Self::aad(f.network, &f.address).as_bytes() })
            .map_err(|_| anyhow::anyhow!("неверный пароль или файл кошелька изменён"))?;
        let words = String::from_utf8(plain).context("файл кошелька повреждён")?;
        let words: Vec<String> = words.split(' ').map(String::from).collect();
        if words.len() != 24 {
            bail!("файл кошелька повреждён");
        }
        Ok(words)
    }

    /// Открывает кошелёк для подписи.
    pub fn unlock(&self, pass: &str) -> Result<Wallet> {
        let f = self.read()?;
        let words = self.reveal(pass)?.join(" ");
        let w = Wallet::from_key_pair(key_pair(&words)?, f.network)?;
        // Адрес, выведенный из ключа, должен совпасть с записанным: иначе показывали бы один адрес, а платили с другого.
        ensure!(w.address_string() == f.address, "адрес в файле не совпадает с ключом");
        Ok(w)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        std::env::temp_dir().join(format!("rift-vault-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed))).join("wallet.json")
    }

    #[test]
    fn generated_words_are_valid_unique_sets() {
        let (a, b) = (generate_words().unwrap(), generate_words().unwrap());
        assert_eq!(a.len(), 24);
        assert_ne!(a, b);
        assert!(Mnemonic::new(a.iter().map(String::as_str).collect(), &None).is_ok());
    }

    #[test]
    fn create_unlock_reveal_and_wrong_password() {
        let v = Vault::new(tmp()).with_kdf(Kdf::FAST);
        assert!(!v.exists());
        let words = v.create("correct horse", Network::Testnet).unwrap();
        let info = v.info().unwrap();
        assert_eq!(info.network, Network::Testnet);
        assert!(info.address.starts_with("0Q"), "тестовая сеть, не возвращаемый: {}", info.address);
        assert_eq!(v.reveal("correct horse").unwrap(), words);
        assert_eq!(v.unlock("correct horse").unwrap().address_string(), info.address);
        assert!(v.unlock("wrong password").is_err());
        assert!(v.create("another password", Network::Testnet).is_err(), "существующий кошелёк не затирается");
        #[cfg(unix)]
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(v.path()).unwrap().permissions()) & 0o777, 0o600);
        // Слова не лежат в файле открытым текстом.
        let raw = std::fs::read_to_string(v.path()).unwrap();
        assert!(!raw.contains(&words[0]) || words[0].len() < 4);
        std::fs::remove_dir_all(v.path().parent().unwrap()).ok();
    }

    #[test]
    fn short_password_and_bad_words_are_rejected() {
        let v = Vault::new(tmp()).with_kdf(Kdf::FAST);
        assert!(v.create("short", Network::Mainnet).is_err());
        assert!(v.import("раз два три", "long enough pass", Network::Mainnet).is_err());
        let r = v.import(&["abandon"; 24].join(" "), "long enough pass", Network::Mainnet);
        assert!(r.is_err(), "неверная контрольная сумма слов: принят {:?}", v.info());
        assert!(!v.exists(), "неудачный ввод ничего не оставляет на диске");
    }

    #[test]
    fn tampering_with_the_file_is_detected() {
        let v = Vault::new(tmp()).with_kdf(Kdf::FAST);
        v.create("correct horse", Network::Mainnet).unwrap();
        let other = Vault::new(tmp()).with_kdf(Kdf::FAST);
        other.create("other password", Network::Mainnet).unwrap();
        let (mut a, b): (serde_json::Value, serde_json::Value) = (serde_json::from_slice(&std::fs::read(v.path()).unwrap()).unwrap(), serde_json::from_slice(&std::fs::read(other.path()).unwrap()).unwrap());
        let write = |a: &serde_json::Value| std::fs::write(v.path(), serde_json::to_vec(a).unwrap()).unwrap();
        // Чужой адрес в открытой части (чтобы показывать один адрес, а платить с другого).
        a["address"] = b["address"].clone();
        write(&a);
        assert!(v.unlock("correct horse").is_err(), "подмена адреса");
        // Другая сеть.
        std::fs::remove_file(v.path()).unwrap();
        v.create("correct horse", Network::Mainnet).unwrap();
        let mut a: serde_json::Value = serde_json::from_slice(&std::fs::read(v.path()).unwrap()).unwrap();
        a["network"] = "testnet".into();
        write(&a);
        assert!(v.unlock("correct horse").is_err(), "подмена сети");
        // Порча шифртекста и слишком дорогие параметры KDF.
        std::fs::remove_file(v.path()).unwrap();
        v.create("correct horse", Network::Mainnet).unwrap();
        let mut a: serde_json::Value = serde_json::from_slice(&std::fs::read(v.path()).unwrap()).unwrap();
        let ct = a["ct"].as_str().unwrap().to_string();
        a["ct"] = format!("AAAA{}", &ct[4..]).into();
        write(&a);
        assert!(v.reveal("correct horse").is_err(), "порча шифртекста");
        a["ct"] = ct.into();
        a["kdf"]["m_kib"] = 4_000_000u32.into();
        write(&a);
        assert!(v.reveal("correct horse").is_err(), "файл не заставит тратить гигабайты памяти");
    }
}
