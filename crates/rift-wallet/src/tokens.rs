//! Монеты кошелька и точная работа с суммами: целые «мельчайшие единицы», десятичная запись только на границе с пользователем.

use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::vault::Network;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    pub symbol: String,
    pub name: String,
    pub decimals: u8,
    /// Адрес мастер-контракта jetton'а; у TON его нет.
    pub master: Option<String>,
}

/// USDT в основной сети TON (jetton, 6 знаков).
pub const USDT_MASTER: &str = "EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs";

impl Token {
    pub fn is_native(&self) -> bool {
        self.master.is_none()
    }
}

/// Монеты по умолчанию. RIFT появится здесь, когда будет выпущен его jetton: адрес мастера пока вписывается в `tokens.json`.
pub fn defaults(network: Network) -> Vec<Token> {
    let t = |symbol: &str, name: &str, decimals: u8, master: Option<&str>| Token { symbol: symbol.into(), name: name.into(), decimals, master: master.map(Into::into) };
    let mut v = vec![t("TON", "Toncoin", 9, None)];
    if network == Network::Mainnet {
        v.push(t("USDT", "Tether USD", 6, Some(USDT_MASTER)));
    }
    v
}

impl Token {
    /// Проверка монеты, введённой человеком или прочитанной из файла.
    pub fn validate(&self) -> Result<()> {
        ensure!(!self.symbol.is_empty() && self.symbol.chars().count() <= 12 && self.symbol.chars().all(|c| c.is_alphanumeric()), "тикер: от 1 до 12 букв и цифр");
        ensure!(self.name.chars().count() <= 40, "название длиннее 40 знаков");
        ensure!(self.decimals <= 18, "знаков после запятой не больше 18");
        if let Some(m) = &self.master {
            m.parse::<tonlib_core::TonAddress>().map_err(|e| anyhow::anyhow!("адрес мастера: {e}"))?;
        }
        Ok(())
    }
}

/// Монеты по умолчанию плюс добавленные пользователем (`tokens.json`). Одноимённые и повторяющиеся по адресу отбрасываются.
pub fn with_extra(network: Network, extra: Vec<Token>) -> Vec<Token> {
    let mut all = defaults(network);
    for t in extra {
        if t.validate().is_ok() && t.master.is_some() && !all.iter().any(|a| a.symbol.eq_ignore_ascii_case(&t.symbol) || a.master == t.master) {
            all.push(t);
        }
    }
    all
}

/// «12.5» → 12_500_000_000 при 9 знаках. Точно: без `f64`, без лишних знаков после запятой, без отрицательных и пустых.
pub fn parse_amount(s: &str, decimals: u8) -> Result<u128> {
    let s = s.trim().replace(',', ".");
    ensure!(!s.is_empty(), "сумма не указана");
    let (int, frac) = s.split_once('.').unwrap_or((&s, ""));
    ensure!(!int.is_empty() || !frac.is_empty(), "сумма не указана");
    ensure!(int.chars().chain(frac.chars()).all(|c| c.is_ascii_digit()), "в сумме допустимы только цифры и одна запятая");
    ensure!(frac.len() <= decimals as usize, "у этой монеты не больше {decimals} знаков после запятой");
    let scale = 10u128.checked_pow(decimals as u32).ok_or_else(|| anyhow::anyhow!("слишком много знаков"))?;
    let whole: u128 = if int.is_empty() { 0 } else { int.parse().map_err(|_| anyhow::anyhow!("сумма слишком велика"))? };
    let mut fr: u128 = if frac.is_empty() { 0 } else { frac.parse()? };
    fr *= 10u128.pow((decimals as usize - frac.len()) as u32);
    let total = whole.checked_mul(scale).and_then(|w| w.checked_add(fr));
    match total {
        Some(t) if t > 0 => Ok(t),
        Some(_) => bail!("сумма должна быть больше нуля"),
        None => bail!("сумма слишком велика"),
    }
}

/// 12_500_000_000 → «12.5». Хвостовые нули убираются.
pub fn format_amount(v: u128, decimals: u8) -> String {
    let scale = 10u128.pow(decimals as u32);
    let (w, f) = (v / scale, v % scale);
    if f == 0 {
        return w.to_string();
    }
    let frac = format!("{f:0width$}", width = decimals as usize);
    format!("{w}.{}", frac.trim_end_matches('0'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_is_exact_and_strict() {
        assert_eq!(parse_amount("1", 9).unwrap(), 1_000_000_000);
        assert_eq!(parse_amount("12.5", 9).unwrap(), 12_500_000_000);
        assert_eq!(parse_amount(" 0,000000001 ", 9).unwrap(), 1, "запятая и пробелы");
        assert_eq!(parse_amount(".5", 6).unwrap(), 500_000);
        assert_eq!(parse_amount("5.", 6).unwrap(), 5_000_000);
        // 0.1 + 0.2 в числах с плавающей точкой неточно; у нас — целые.
        assert_eq!(parse_amount("0.1", 9).unwrap() + parse_amount("0.2", 9).unwrap(), parse_amount("0.3", 9).unwrap());
        for bad in ["", " ", ".", "0", "0.0", "-1", "+1", "1e3", "1.2.3", "abc", "1 000", "1.0000001", "0x10", "340282366920938463463374607431768211455.1"] {
            assert!(parse_amount(bad, 6).is_err(), "«{bad}» должно отвергаться");
        }
        assert!(parse_amount("340282366920938463463374607431768211456", 0).is_err(), "переполнение");
    }

    #[test]
    fn format_roundtrips() {
        for (v, d, s) in [(12_500_000_000u128, 9u8, "12.5"), (1, 9, "0.000000001"), (5_000_000, 6, "5"), (0, 6, "0"), (123_456_789, 6, "123.456789")] {
            assert_eq!(format_amount(v, d), s);
            if v > 0 {
                assert_eq!(parse_amount(s, d).unwrap(), v);
            }
        }
    }

    #[test]
    fn extra_tokens_are_validated_and_deduplicated() {
        let t = |s: &str, d: u8, m: Option<&str>| Token { symbol: s.into(), name: s.into(), decimals: d, master: m.map(Into::into) };
        let rift = t("RIFT", 9, Some(USDT_MASTER)); // адрес любой допустимый
        assert_eq!(with_extra(Network::Testnet, vec![rift.clone()]).len(), 2);
        let bad = [t("", 9, Some(USDT_MASTER)), t("X Y", 9, Some(USDT_MASTER)), t("R", 19, Some(USDT_MASTER)), t("R", 9, Some("не адрес")), t("TON", 9, Some(USDT_MASTER)), t("NATIVE", 9, None)];
        assert_eq!(with_extra(Network::Testnet, bad.to_vec()).len(), 1, "ничего из плохого не принято");
        assert_eq!(with_extra(Network::Mainnet, vec![t("ONE", 6, Some(USDT_MASTER))]).len(), 2, "тот же мастер, что у USDT, второй раз не добавляется");
    }

    #[test]
    fn usdt_only_on_mainnet() {
        assert_eq!(defaults(Network::Mainnet).iter().map(|t| t.symbol.as_str()).collect::<Vec<_>>(), ["TON", "USDT"]);
        assert_eq!(defaults(Network::Testnet).len(), 1);
    }
}
