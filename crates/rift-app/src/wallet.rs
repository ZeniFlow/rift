//! Кошелёк в приложении: состояние (ключ в памяти только пока разблокирован) и команды для страницы `browser://wallet`.
//! Пароль и слова проходят только через эти команды; страницы сайтов к ним доступа не имеют (см. capabilities).

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use rift_wallet::{
    TonAddress,
    api::Api,
    tokens::{self, Token},
    vault::{Kdf, Network, Vault},
    wallet::{Wallet, parse_dest},
};
use serde_json::{Value, json};
use tauri::State;

use crate::browser::Core;

/// Через столько без обращений ключ стирается из памяти.
pub const AUTO_LOCK: Duration = Duration::from_secs(5 * 60);

pub struct WalletState {
    dir: Option<PathBuf>,
    kdf: Mutex<Kdf>,
    /// Другой сервер API вместо публичного (проверки и свой узел).
    api_url: Mutex<Option<String>>,
    unlocked: Mutex<Option<(Arc<Wallet>, Instant)>>,
}

impl WalletState {
    pub fn new(dir: Option<&Path>) -> Self {
        Self { dir: dir.map(Path::to_path_buf), kdf: Mutex::new(Kdf::STRONG), api_url: Mutex::default(), unlocked: Mutex::default() }
    }

    /// Только для самопроверок: быстрый KDF и свой API.
    pub fn for_test(&self, kdf: Kdf, api_url: Option<String>) {
        *self.kdf.lock().unwrap() = kdf;
        *self.api_url.lock().unwrap() = api_url;
    }

    fn vault(&self) -> Result<Vault, String> {
        let dir = self.dir.as_ref().ok_or("кошелёк недоступен: нет каталога данных")?;
        Ok(Vault::new(dir.join("wallet.json")).with_kdf(*self.kdf.lock().unwrap()))
    }

    /// Разблокированный кошелёк; просроченный стирается.
    fn current(&self) -> Option<Arc<Wallet>> {
        let mut g = self.unlocked.lock().unwrap();
        match g.as_mut() {
            Some((w, t)) if t.elapsed() < AUTO_LOCK => {
                *t = Instant::now();
                Some(w.clone())
            }
            Some(_) => {
                *g = None;
                None
            }
            None => None,
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.current().is_some()
    }

    pub fn lock(&self) {
        *self.unlocked.lock().unwrap() = None;
    }

    fn api(&self, network: Network) -> Result<Api, String> {
        let url = self.api_url.lock().unwrap().clone();
        match url {
            Some(u) => Api::new(&u, None),
            None => Api::for_network(network, None),
        }
        .map_err(|e| format!("{e:#}"))
    }

    fn extra_tokens(&self) -> Vec<Token> {
        self.dir.as_ref().and_then(|d| std::fs::read(d.join("tokens.json")).ok()).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    fn tokens(&self, network: Network) -> Vec<Token> {
        tokens::with_extra(network, self.extra_tokens())
    }
}

fn now() -> u32 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as u32)
}

fn e(err: impl std::fmt::Display) -> String {
    format!("{err:#}")
}

fn state(core: &Core) -> &WalletState {
    &core.wallet
}

#[tauri::command]
pub fn wallet_status(core: State<'_, Arc<Core>>) -> Value {
    let w = state(&core);
    let Ok(vault) = w.vault() else { return json!({ "available": false }) };
    match vault.info() {
        Ok(i) if vault.exists() => json!({ "available": true, "exists": true, "unlocked": w.current().is_some(), "network": i.network, "address": i.address }),
        _ => json!({ "available": true, "exists": false }),
    }
}

/// Создаёт кошелёк, сразу его разблокирует и возвращает 24 слова: показать их надо один раз и дать записать.
#[tauri::command]
pub async fn wallet_create(password: String, network: Network, core: State<'_, Arc<Core>>) -> Result<Vec<String>, String> {
    let w = state(&core);
    let vault = w.vault()?;
    let words = tokio::task::spawn_blocking({
        let v = w.vault()?;
        move || v.create(&password, network).map(|words| (words, password))
    })
    .await
    .map_err(e)?
    .map_err(e)?;
    let (words, password) = words;
    unlock_with(w, &vault, &password).await?;
    Ok(words)
}

#[tauri::command]
pub async fn wallet_import(words: String, password: String, network: Network, core: State<'_, Arc<Core>>) -> Result<(), String> {
    let w = state(&core);
    let vault = w.vault()?;
    let pw = password.clone();
    tokio::task::spawn_blocking({
        let v = w.vault()?;
        move || v.import(&words, &password, network)
    })
    .await
    .map_err(e)?
    .map_err(e)?;
    unlock_with(w, &vault, &pw).await
}

async fn unlock_with(w: &WalletState, vault: &Vault, password: &str) -> Result<(), String> {
    let (path, kdf, pw) = (vault.path().to_path_buf(), *w.kdf.lock().unwrap(), password.to_string());
    let wallet = tokio::task::spawn_blocking(move || Vault::new(path).with_kdf(kdf).unlock(&pw)).await.map_err(e)?.map_err(e)?;
    *w.unlocked.lock().unwrap() = Some((Arc::new(wallet), Instant::now()));
    Ok(())
}

#[tauri::command]
pub async fn wallet_unlock(password: String, core: State<'_, Arc<Core>>) -> Result<(), String> {
    let w = state(&core);
    let vault = w.vault()?;
    unlock_with(w, &vault, &password).await
}

#[tauri::command]
pub fn wallet_lock(core: State<'_, Arc<Core>>) {
    state(&core).lock();
}

/// Слова для резервной копии: каждый раз с паролем, даже если кошелёк разблокирован.
#[tauri::command]
pub async fn wallet_reveal(password: String, core: State<'_, Arc<Core>>) -> Result<Vec<String>, String> {
    let v = state(&core).vault()?;
    tokio::task::spawn_blocking(move || v.reveal(&password)).await.map_err(e)?.map_err(e)
}

/// Монеты и их остатки. Работает и без пароля: нужен только адрес.
#[tauri::command]
pub async fn wallet_balances(core: State<'_, Arc<Core>>) -> Result<Vec<Value>, String> {
    let w = state(&core);
    let info = w.vault()?.info().map_err(e)?;
    let owner: TonAddress = info.address.parse().map_err(|x| e(format!("адрес кошелька: {x}")))?;
    let api = w.api(info.network)?;
    let mut out = vec![];
    for (i, t) in w.tokens(info.network).into_iter().enumerate() {
        if i > 0 {
            tokio::time::sleep(Duration::from_millis(300)).await; // публичный API без ключа: не чаще нескольких запросов в секунду
        }
        let r = api.token_balance(&owner, &t).await;
        out.push(match r {
            Ok(b) => json!({ "symbol": t.symbol, "name": t.name, "decimals": t.decimals, "master": t.master, "raw": b.to_string(), "shown": tokens::format_amount(b, t.decimals) }),
            Err(err) => json!({ "symbol": t.symbol, "name": t.name, "decimals": t.decimals, "master": t.master, "error": e(err) }),
        });
    }
    Ok(out)
}

#[tauri::command]
pub async fn wallet_history(limit: u32, core: State<'_, Arc<Core>>) -> Result<Vec<Value>, String> {
    let w = state(&core);
    let info = w.vault()?.info().map_err(e)?;
    let owner: TonAddress = info.address.parse().map_err(e)?;
    let txs = w.api(info.network)?.history(&owner, limit.clamp(1, 50)).await.map_err(e)?;
    Ok(txs.into_iter().map(|t| json!({ "time": t.time, "hash": t.hash, "incoming": t.incoming, "peer": t.peer, "amount": tokens::format_amount(t.nano, 9), "fee": tokens::format_amount(t.fee, 9), "comment": t.comment })).collect())
}

/// Проверка перевода до окна подтверждения: адрес, сеть, сумма (точно, с учётом знаков монеты). Возвращает то, что покажем человеку.
#[tauri::command]
pub fn wallet_check_send(symbol: String, to: String, amount: String, core: State<'_, Arc<Core>>) -> Result<Value, String> {
    let w = state(&core);
    let info = w.vault()?.info().map_err(e)?;
    let token = w.tokens(info.network).into_iter().find(|t| t.symbol == symbol).ok_or_else(|| format!("нет монеты {symbol}"))?;
    let d = parse_dest(&to, info.network).map_err(e)?;
    let raw = tokens::parse_amount(&amount, token.decimals).map_err(e)?;
    Ok(json!({ "bounce": d.bounce, "friendly": d.addr.to_base64_url_flags(!d.bounce, info.network.is_testnet()), "amount": tokens::format_amount(raw, token.decimals) }))
}

/// Перевод. Подтверждение суммы и адреса человеком делает страница до вызова; здесь только проверки и подпись.
#[tauri::command]
pub async fn wallet_send(symbol: String, to: String, amount: String, comment: Option<String>, core: State<'_, Arc<Core>>) -> Result<(), String> {
    let w = state(&core);
    let wallet = w.current().ok_or("кошелёк заблокирован: введите пароль")?;
    let token = w.tokens(wallet.network()).into_iter().find(|t| t.symbol == symbol).ok_or_else(|| format!("нет монеты {symbol}"))?;
    let dest = parse_dest(&to, wallet.network()).map_err(e)?;
    let raw = tokens::parse_amount(&amount, token.decimals).map_err(e)?;
    let api = w.api(wallet.network())?;
    if token.is_native() {
        api.send_ton(&wallet, &dest, raw, comment.as_deref(), now()).await.map_err(e)
    } else {
        api.send_jetton(&wallet, &token, &dest, raw, now()).await.map_err(e)
    }
}

/// Добавляет jetton (например RIFT, когда будет выпущен) в список монет.
#[tauri::command]
pub fn wallet_add_token(symbol: String, name: String, decimals: u8, master: String, core: State<'_, Arc<Core>>) -> Result<(), String> {
    let w = state(&core);
    let dir = w.dir.clone().ok_or("нет каталога данных")?;
    let t = Token { symbol: symbol.trim().to_uppercase(), name: name.trim().into(), decimals, master: Some(master.trim().into()) };
    t.validate().map_err(e)?;
    let net = w.vault()?.info().map_err(e)?.network;
    let mut extra = w.extra_tokens();
    if tokens::with_extra(net, [extra.clone(), vec![t.clone()]].concat()).len() == tokens::with_extra(net, extra.clone()).len() {
        return Err("такая монета уже есть (тот же тикер или адрес)".into());
    }
    extra.push(t);
    std::fs::write(dir.join("tokens.json"), serde_json::to_vec_pretty(&extra).map_err(e)?).map_err(e)
}

/// Удаляет кошелёк с устройства (после подтверждения на странице). Без резервной копии слов деньги потеряны.
#[tauri::command]
pub fn wallet_forget(core: State<'_, Arc<Core>>) -> Result<(), String> {
    let w = state(&core);
    let v = w.vault()?;
    w.lock();
    std::fs::remove_file(v.path()).map_err(e)
}
