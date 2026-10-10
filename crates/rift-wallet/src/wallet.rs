//! Подпись переводов кошельком V4R2. Ничего не знает о сети: seqno и время приходят снаружи, результат — BOC в base64
//! для `sendBoc`. Поэтому всё проверяется тестами без сети: подписанное сообщение разбирается обратно и сверяется.

use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use num_bigint::BigUint;
use tonlib_core::{
    TonAddress,
    cell::{ArcCell, BagOfCells, Cell, CellBuilder},
    message::{CommonMsgInfo, InternalMessage, JettonTransferMessage, TonMessage, TransferMessage},
    wallet::{mnemonic::KeyPair, ton_wallet::TonWallet},
};

use crate::vault::{Network, VERSION};

/// Сколько TON прикладывается к переводу jetton'а: контракты jetton'ов берут из них комиссию, остаток возвращается отправителю.
pub const JETTON_GAS: u128 = 50_000_000;
/// Подпись действует ограниченное время: зависшее сообщение потом не «выстрелит».
pub const TTL_SECS: u32 = 300;

pub struct Wallet {
    inner: TonWallet,
    network: Network,
}

/// Получатель: адрес и признак «возвращать при ошибке» (так записан адрес: EQ… возвращаемый, UQ… нет).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dest {
    pub addr: TonAddress,
    pub bounce: bool,
}

/// Разбор адреса от человека. Адрес тестовой сети в основной (и наоборот) отвергается: так деньги не уходят «в никуда».
pub fn parse_dest(s: &str, network: Network) -> Result<Dest> {
    let s = s.trim();
    let flags = if s.len() == 48 {
        if s.contains(['-', '_']) { TonAddress::from_base64_url_flags(s) } else { TonAddress::from_base64_std_flags(s) }.map_err(|e| anyhow::anyhow!("{e}"))?
    } else {
        // Сырой вид «0:hex». Без признаков: считаем невозвращаемым, как и принято для новых получателей.
        (TonAddress::from_hex_str(s).map_err(|e| anyhow::anyhow!("не адрес TON: {e}"))?, true, network.is_testnet())
    };
    let (addr, non_bounceable, testnet) = flags;
    ensure!(testnet == network.is_testnet(), "это адрес {} сети, а кошелёк в {}", if testnet { "тестовой" } else { "основной" }, if network.is_testnet() { "тестовой" } else { "основной" });
    ensure!(addr.workchain == 0, "поддерживается только основной воркчейн (0)");
    Ok(Dest { addr, bounce: !non_bounceable })
}

fn internal(dest: &TonAddress, bounce: bool, value: u128, body: Cell) -> Result<ArcCell> {
    let info = CommonMsgInfo::InternalMessage(InternalMessage {
        ihr_disabled: true,
        bounce,
        bounced: false,
        src: TonAddress::NULL,
        dest: dest.clone(),
        value: BigUint::from(value),
        ihr_fee: BigUint::from(0u8),
        fwd_fee: BigUint::from(0u8),
        created_lt: 0,
        created_at: 0,
    });
    Ok(TransferMessage::new(info, body.to_arc()).build().map_err(|e| anyhow::anyhow!("{e}"))?.to_arc())
}

impl Wallet {
    pub fn from_key_pair(kp: KeyPair, network: Network) -> Result<Self> {
        Ok(Self { inner: TonWallet::new(VERSION, kp).map_err(|e| anyhow::anyhow!("{e}"))?, network })
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn address(&self) -> &TonAddress {
        &self.inner.address
    }

    /// Адрес для показа и приёма: не возвращаемый, url-safe.
    pub fn address_string(&self) -> String {
        self.inner.address.to_base64_url_flags(true, self.network.is_testnet())
    }

    pub fn public_key(&self) -> &[u8] {
        &self.inner.key_pair.public_key
    }

    /// Внешнее сообщение кошельку с подписью. `deployed == false` — кошелёк ещё не создан в сети: к первому переводу прикладываем код.
    fn external(&self, msg: ArcCell, seqno: u32, now: u32, deployed: bool) -> Result<String> {
        let cell = self.inner.create_external_msg(now.saturating_add(TTL_SECS), seqno, !deployed, [msg]).map_err(|e| anyhow::anyhow!("{e}"))?;
        let boc = BagOfCells::from_root(cell).serialize(false).map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(B64.encode(boc))
    }

    /// Перевод TON. Комментарий — обычный текст в теле (до ~120 байт в одной ячейке).
    pub fn ton_transfer(&self, to: &Dest, nano: u128, comment: Option<&str>, seqno: u32, now: u32, deployed: bool) -> Result<String> {
        ensure!(nano > 0, "сумма должна быть больше нуля");
        let body = match comment.filter(|c| !c.is_empty()) {
            Some(c) => {
                ensure!(c.len() <= 120, "комментарий длиннее 120 байт");
                let mut b = CellBuilder::new();
                b.store_u32(32, 0).and_then(|b| b.store_string(c)).map_err(|e| anyhow::anyhow!("{e}"))?;
                b.build().map_err(|e| anyhow::anyhow!("{e}"))?
            }
            None => CellBuilder::new().build().map_err(|e| anyhow::anyhow!("{e}"))?,
        };
        self.external(internal(&to.addr, to.bounce, nano, body)?, seqno, now, deployed)
    }

    /// Перевод jetton'а через его кошелёк (адрес кошелька jetton'а этого владельца определяет сеть, см. `Api::jetton_wallet`).
    /// Остаток приложенных TON вернётся на этот же кошелёк.
    pub fn jetton_transfer(&self, jetton_wallet: &TonAddress, to: &Dest, amount: u128, seqno: u32, now: u32, deployed: bool) -> Result<String> {
        ensure!(amount > 0, "сумма должна быть больше нуля");
        let mut t = JettonTransferMessage::new(&to.addr, &BigUint::from(amount));
        t.with_response_destination(&self.inner.address);
        let body = t.build().map_err(|e| anyhow::anyhow!("{e}"))?;
        self.external(internal(jetton_wallet, true, JETTON_GAS, body)?, seqno, now, deployed)
    }
}

#[cfg(test)]
pub mod check {
    use anyhow::Context;

    use super::*;

    /// Что видно в подписанном сообщении: для проверки перед отправкой и в тестах.
    #[derive(Debug, PartialEq, Eq)]
    pub struct Decoded {
        pub seqno: u32,
        pub valid_until: u32,
        pub dest: TonAddress,
        pub value: u128,
        pub bounce: bool,
        pub has_state_init: bool,
        /// Тело внутреннего сообщения: опкод (0 — текст, 0x0f8a7ea5 — перевод jetton'а) и остальное.
        pub opcode: u32,
        pub text: Option<String>,
        pub jetton_amount: Option<u128>,
        pub jetton_dest: Option<TonAddress>,
        pub signature_ok: bool,
    }

    /// Разбирает BOC внешнего сообщения V4R2 и проверяет подпись открытым ключом. Нужен тестам и защите от собственных ошибок.
    pub fn decode(boc_b64: &str, public_key: &[u8]) -> Result<Decoded> {
        use tonlib_core::cell::TonCellError;
        use tonlib_core::tlb_types::{block::message::Message, tlb::TLB};
        let e = |x: TonCellError| anyhow::anyhow!("{x}");
        let m = Message::from_boc_b64(boc_b64).map_err(e)?;
        let has_state_init = m.init.is_some();
        let body: ArcCell = m.body.value.clone();
        let mut b = body.parser();
        let signature = b.load_bytes(64).map_err(e)?;
        // Подписан хэш остатка тела: пересоберём ячейку без подписи.
        let rest_bits = body.bit_len() - 512;
        let mut rest = CellBuilder::new();
        let mut q = body.parser();
        q.load_bytes(64).map_err(e)?;
        let tail = q.load_bits(rest_bits).map_err(e)?;
        rest.store_bits(rest_bits, &tail).map_err(e)?;
        for r in body.references() {
            rest.store_reference(r).map_err(e)?;
        }
        let signed = rest.build().map_err(e)?;
        let signature_ok = {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            let key = VerifyingKey::from_bytes(public_key.try_into().context("ключ не 32 байта")?).context("ключ")?;
            key.verify(signed.cell_hash().as_slice(), &Signature::from_slice(&signature).context("подпись")?).is_ok()
        };
        let _subwallet = b.load_u32(32).map_err(e)?;
        let valid_until = b.load_u32(32).map_err(e)?;
        let seqno = b.load_u32(32).map_err(e)?;
        let _op = b.load_u8(8).map_err(e)?;
        let _mode = b.load_u8(8).map_err(e)?;
        let msg = body.reference(0).map_err(e)?.clone();
        let mut m = msg.parser();
        ensure!(!m.load_bit().map_err(e)?, "не внутреннее сообщение");
        let _ihr = m.load_bit().map_err(e)?;
        let bounce = m.load_bit().map_err(e)?;
        let _bounced = m.load_bit().map_err(e)?;
        let _src = m.load_address().map_err(e)?;
        let dest = m.load_address().map_err(e)?;
        let value = m.load_coins().map_err(e)?;
        m.load_bit().map_err(e)?; // extra currencies
        m.load_coins().map_err(e)?;
        m.load_coins().map_err(e)?;
        m.load_u64(64).map_err(e)?;
        m.load_u32(32).map_err(e)?;
        ensure!(!m.load_bit().map_err(e)?, "в сообщении кошелька есть state_init");
        let inner_in_ref = m.load_bit().map_err(e)?;
        let mut text = None;
        let (mut opcode, mut jetton_amount, mut jetton_dest) = (0, None, None);
        let inner_cell;
        let mut ip = if inner_in_ref {
            inner_cell = msg.reference(0).map_err(e)?.clone();
            inner_cell.parser()
        } else {
            m
        };
        if ip.remaining_bits() >= 32 {
            opcode = ip.load_u32(32).map_err(e)?;
            if opcode == 0 {
                let rest = ip.remaining_bits();
                let bytes = ip.load_bytes(rest / 8).map_err(e)?;
                text = Some(String::from_utf8_lossy(&bytes).into_owned());
            } else if opcode == 0x0f8a7ea5 {
                ip.load_u64(64).map_err(e)?;
                jetton_amount = Some(ip.load_coins().map_err(e)?.try_into().context("сумма jetton'а слишком велика")?);
                jetton_dest = Some(ip.load_address().map_err(e)?);
            }
        }
        Ok(Decoded { seqno, valid_until, dest, value: value.try_into().context("слишком большая сумма")?, bounce, has_state_init, opcode, text, jetton_amount, jetton_dest, signature_ok })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use tonlib_core::wallet::mnemonic::Mnemonic;

    use super::{check::decode, *};
    use crate::vault::{Kdf, Vault};

    /// Набор слов и адрес V4R2 из тестов tonlib-core (сверено с другими реализациями TON).
    const WORDS: &str = "fancy carpet hello mandate penalty trial consider property top vicious exit rebuild tragic profit urban major total month holiday sudden rib gather media vicious";
    const V4R2_ADDR: &str = "EQCDM_QGggZ3qMa_f3lRPk4_qLDnLTqdi6OkMAV2NB9r5TG3";
    const OTHER_MAIN: &str = "EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs";

    fn wallet(network: Network) -> Wallet {
        Wallet::from_key_pair(Mnemonic::from_str(WORDS, &None).unwrap().to_key_pair().unwrap(), network).unwrap()
    }

    #[test]
    fn address_matches_known_v4r2_vector_and_vault_agrees() {
        let w = wallet(Network::Mainnet);
        assert_eq!(*w.address(), TonAddress::from_str(V4R2_ADDR).unwrap());
        assert!(w.address_string().starts_with("UQ"), "не возвращаемый адрес основной сети: {}", w.address_string());
        let path = std::env::temp_dir().join(format!("rift-wallet-w-{}", std::process::id())).join("w.json");
        let v = Vault::new(&path).with_kdf(Kdf::FAST);
        v.import(WORDS, "correct horse", Network::Mainnet).unwrap();
        assert_eq!(v.info().unwrap().address, w.address_string());
        assert_eq!(v.unlock("correct horse").unwrap().address(), w.address());
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn ton_transfer_is_signed_and_says_what_was_asked() {
        let w = wallet(Network::Mainnet);
        let to = parse_dest(OTHER_MAIN, Network::Mainnet).unwrap();
        assert!(to.bounce, "EQ… — возвращаемый адрес");
        let boc = w.ton_transfer(&to, 1_500_000_000, Some("привет"), 7, 1_000, true).unwrap();
        let d = decode(&boc, w.public_key()).unwrap();
        assert!(d.signature_ok);
        assert_eq!((d.seqno, d.valid_until, d.value, d.bounce, d.has_state_init), (7, 1_000 + TTL_SECS, 1_500_000_000, true, false));
        assert_eq!(d.dest, to.addr);
        assert_eq!(d.text.as_deref(), Some("привет"));
        // Подпись принадлежит именно этому ключу.
        let other = decode(&boc, wallet(Network::Mainnet).public_key()).unwrap();
        assert!(other.signature_ok);
        let mut bad_key = w.public_key().to_vec();
        bad_key[0] ^= 1;
        assert!(decode(&boc, &bad_key).map_or(true, |d| !d.signature_ok), "чужой ключ подпись не проверяет");
    }

    #[test]
    fn nondeployed_wallet_attaches_state_init_and_amounts_are_validated() {
        let w = wallet(Network::Mainnet);
        let to = parse_dest(&TonAddress::from_str(OTHER_MAIN).unwrap().to_base64_url_flags(true, false), Network::Mainnet).unwrap();
        assert!(!to.bounce, "UQ… — не возвращаемый");
        let first = decode(&w.ton_transfer(&to, 1, None, 0, 5, false).unwrap(), w.public_key()).unwrap();
        assert!(first.has_state_init && first.signature_ok && first.text.is_none());
        assert!(w.ton_transfer(&to, 0, None, 0, 5, true).is_err(), "нулевая сумма");
        assert!(w.ton_transfer(&to, 1, Some(&"я".repeat(61)), 0, 5, true).is_err(), "длинный комментарий");
    }

    #[test]
    fn jetton_transfer_targets_the_jetton_wallet_with_gas_and_right_receiver() {
        let w = wallet(Network::Mainnet);
        let jw = TonAddress::from_str(OTHER_MAIN).unwrap();
        let to = parse_dest(&w.address().to_base64_url(), Network::Mainnet).unwrap();
        let d = decode(&w.jetton_transfer(&jw, &to, 12_345_678, 3, 100, true).unwrap(), w.public_key()).unwrap();
        assert!(d.signature_ok);
        assert_eq!((d.opcode, d.jetton_amount, d.value, d.bounce), (0x0f8a7ea5, Some(12_345_678), JETTON_GAS, true));
        assert_eq!(d.dest, jw, "сообщение уходит в кошелёк jetton'а, а не получателю");
        assert_eq!(d.jetton_dest, Some(to.addr.clone()), "получатель jetton'а внутри");
        assert!(w.jetton_transfer(&jw, &to, 0, 3, 100, true).is_err());
    }

    #[test]
    fn parse_dest_rejects_wrong_network_and_garbage() {
        let main = TonAddress::from_str(V4R2_ADDR).unwrap();
        let test_addr = main.to_base64_url_flags(true, true);
        assert!(parse_dest(&test_addr, Network::Mainnet).is_err(), "адрес тестовой сети в основной");
        assert!(parse_dest(V4R2_ADDR, Network::Testnet).is_err(), "адрес основной сети в тестовой");
        assert!(parse_dest(&test_addr, Network::Testnet).is_ok());
        assert_eq!(parse_dest(&format!("  {V4R2_ADDR} "), Network::Mainnet).unwrap().addr, main, "пробелы по краям");
        assert_eq!(parse_dest(&main.to_hex(), Network::Mainnet).unwrap().addr, main, "сырой вид 0:hex");
        for bad in ["", "hello", "EQ", &V4R2_ADDR[..47], &format!("{}A", V4R2_ADDR), "-1:0000000000000000000000000000000000000000000000000000000000000000"] {
            assert!(parse_dest(bad, Network::Mainnet).is_err(), "«{bad}» должно отвергаться");
        }
        // Опечатка в одном знаке ломает контрольную сумму адреса.
        let mut typo = V4R2_ADDR.to_string();
        typo.replace_range(10..11, if &V4R2_ADDR[10..11] == "A" { "B" } else { "A" });
        assert!(parse_dest(&typo, Network::Mainnet).is_err(), "опечатка в адресе");
    }
}
