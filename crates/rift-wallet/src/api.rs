//! Чтение сети и отправка: HTTP API в стиле toncenter v2. Любой сервер с этим интерфейсом подойдёт (можно свой).
//! Сервер не может подделать подпись, но может соврать о балансе или seqno, поэтому перед отправкой jetton'ов
//! проверяем остаток и TON на комиссию, а сообщения подписываем с коротким сроком действия.

use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use hyper::Method;
use serde_json::{Value, json};
use tonlib_core::{
    TonAddress,
    cell::{BagOfCells, CellBuilder},
};
use url::Url;

use crate::{
    http,
    tokens::Token,
    vault::Network,
    wallet::{Dest, JETTON_GAS, Wallet},
};

pub struct Api {
    base: Url,
    key: Option<String>,
}

/// Запись в истории TON-переводов.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Tx {
    pub time: u64,
    pub hash: String,
    /// `true` — входящий.
    pub incoming: bool,
    /// Адрес второй стороны (пусто у служебных).
    pub peer: String,
    pub nano: u128,
    pub fee: u128,
    pub comment: String,
}

fn num(v: &Value) -> Result<u128> {
    match v {
        Value::String(s) => s.parse().with_context(|| format!("не число: {s}")),
        Value::Number(n) => n.as_u64().map(u128::from).context("не целое число"),
        _ => bail!("ожидалось число"),
    }
}

/// Минимум TON на счёте сверх суммы перевода: комиссия сети. Консервативная оценка, остаток вернётся.
pub const FEE_RESERVE: u128 = 10_000_000;

impl Api {
    pub fn new(base: &str, key: Option<String>) -> Result<Self> {
        let mut base = Url::parse(base).context("адрес API")?;
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        Ok(Self { base, key })
    }

    pub fn for_network(network: Network, key: Option<String>) -> Result<Self> {
        Self::new(network.api_url(), key)
    }

    /// Один запрос. Сервер без ключа отвечает 429, если спрашивать чаще раза в секунду: ждём и повторяем один раз.
    async fn call(&self, method: Method, path: &str, query: &[(&str, &str)], body: Option<Value>) -> Result<Value> {
        let mut url = self.base.join(path)?;
        for (k, v) in query {
            url.query_pairs_mut().append_pair(k, v);
        }
        let headers: Vec<(&str, &str)> = self.key.as_deref().map(|k| ("x-api-key", k)).into_iter().collect();
        for attempt in 0..2 {
            let (status, bytes) = http::request(method.clone(), &url, &headers, body.as_ref().map(|b| b.to_string().into_bytes())).await?;
            if status == 429 && attempt == 0 {
                tokio::time::sleep(Duration::from_millis(1200)).await;
                continue;
            }
            let v: Value = serde_json::from_slice(&bytes).with_context(|| format!("ответ сервера ({status}) не JSON"))?;
            if v["ok"] == true {
                return Ok(v["result"].clone());
            }
            bail!("сервер отказал ({status}): {}", v["error"].as_str().unwrap_or("без пояснения"));
        }
        bail!("сервер просит подождать (429)")
    }

    /// Баланс TON в нанотонах.
    pub async fn balance(&self, addr: &TonAddress) -> Result<u128> {
        num(&self.call(Method::GET, "getAddressBalance", &[("address", &addr.to_base64_url())], None).await?)
    }

    /// (seqno, создан ли кошелёк в сети). У несозданного seqno = 0.
    pub async fn seqno(&self, addr: &TonAddress) -> Result<(u32, bool)> {
        let info = self.call(Method::GET, "getAddressInformation", &[("address", &addr.to_base64_url())], None).await?;
        if info["state"] != "active" {
            return Ok((0, false));
        }
        let r = self.run(addr, "seqno", vec![]).await?;
        let n = r.first().and_then(|e| e.get(1)).context("нет seqno в ответе")?;
        Ok((u32::try_from(parse_num(n)?).context("seqno слишком велик")?, true))
    }

    /// Запуск get-метода: возвращает стек как есть (`[["num","0x…"], ["cell",{"bytes":…}], …]`).
    async fn run(&self, addr: &TonAddress, method: &str, stack: Vec<Value>) -> Result<Vec<Value>> {
        let r = self.call(Method::POST, "runGetMethod", &[], Some(json!({ "address": addr.to_base64_url(), "method": method, "stack": stack }))).await?;
        // 0 и 1 — штатное завершение TVM.
        ensure!(matches!(r["exit_code"].as_i64(), Some(0 | 1)), "метод {method} завершился с кодом {}", r["exit_code"]);
        Ok(r["stack"].as_array().context("нет стека")?.clone())
    }

    /// Адрес кошелька jetton'а у владельца.
    pub async fn jetton_wallet(&self, master: &TonAddress, owner: &TonAddress) -> Result<TonAddress> {
        let mut b = CellBuilder::new();
        b.store_address(owner).map_err(|e| anyhow::anyhow!("{e}"))?;
        let boc = BagOfCells::from_root(b.build().map_err(|e| anyhow::anyhow!("{e}"))?).serialize(false).map_err(|e| anyhow::anyhow!("{e}"))?;
        let stack = self.run(master, "get_wallet_address", vec![json!(["tvm.Slice", B64.encode(boc)])]).await?;
        address_from_stack(stack.first().context("пустой стек")?)
    }

    /// Баланс jetton'а в мельчайших единицах. Нет кошелька jetton'а у владельца — ноль (его ещё не создавали).
    pub async fn jetton_balance(&self, master: &TonAddress, owner: &TonAddress) -> Result<u128> {
        let jw = self.jetton_wallet(master, owner).await?;
        match self.run(&jw, "get_wallet_data", vec![]).await {
            Ok(st) => parse_num(st.first().and_then(|e| e.get(1)).context("нет баланса")?),
            Err(_) => Ok(0), // контракт ещё не создан: runGetMethod отвечает ошибкой
        }
    }

    pub async fn send_boc(&self, boc_b64: &str) -> Result<()> {
        self.call(Method::POST, "sendBoc", &[], Some(json!({ "boc": boc_b64 }))).await.map(|_| ())
    }

    pub async fn history(&self, addr: &TonAddress, limit: u32) -> Result<Vec<Tx>> {
        let r = self.call(Method::GET, "getTransactions", &[("address", &addr.to_base64_url()), ("limit", &limit.to_string()), ("archival", "false")], None).await?;
        Ok(r.as_array().context("нет списка")?.iter().filter_map(parse_tx).collect())
    }

    /// Баланс монеты кошелька.
    pub async fn token_balance(&self, owner: &TonAddress, t: &Token) -> Result<u128> {
        match &t.master {
            None => self.balance(owner).await,
            Some(m) => self.jetton_balance(&m.parse().map_err(|e| anyhow::anyhow!("мастер {}: {e}", t.symbol))?, owner).await,
        }
    }

    /// Перевод TON: сверка баланса, seqno, подпись, отправка.
    pub async fn send_ton(&self, w: &Wallet, to: &Dest, nano: u128, comment: Option<&str>, now: u32) -> Result<()> {
        let have = self.balance(w.address()).await?;
        ensure!(have >= nano.saturating_add(FEE_RESERVE), "недостаточно TON: на счёте {have} нано, нужно {nano} и ещё {FEE_RESERVE} на комиссию");
        let (seqno, deployed) = self.seqno(w.address()).await?;
        self.send_boc(&w.ton_transfer(to, nano, comment, seqno, now, deployed)?).await
    }

    /// Перевод jetton'а: проверяем и остаток jetton'а, и TON на газ.
    pub async fn send_jetton(&self, w: &Wallet, t: &Token, to: &Dest, amount: u128, now: u32) -> Result<()> {
        let master: TonAddress = t.master.as_deref().with_context(|| format!("{} не jetton", t.symbol))?.parse().map_err(|e| anyhow::anyhow!("мастер {}: {e}", t.symbol))?;
        let jw = self.jetton_wallet(&master, w.address()).await?;
        let (have_j, have_ton) = (self.jetton_balance(&master, w.address()).await?, self.balance(w.address()).await?);
        ensure!(have_j >= amount, "недостаточно {}: на счёте {have_j}, нужно {amount} (в мельчайших единицах)", t.symbol);
        ensure!(have_ton >= JETTON_GAS + FEE_RESERVE, "для перевода {} нужно хотя бы {} нано TON на газ, на счёте {have_ton}", t.symbol, JETTON_GAS + FEE_RESERVE);
        let (seqno, deployed) = self.seqno(w.address()).await?;
        self.send_boc(&w.jetton_transfer(&jw, to, amount, seqno, now, deployed)?).await
    }
}

fn parse_num(v: &Value) -> Result<u128> {
    let s = v.as_str().context("число ожидалось строкой")?;
    match s.strip_prefix("0x") {
        Some(h) => u128::from_str_radix(h, 16).with_context(|| format!("не число: {s}")),
        None => s.parse().with_context(|| format!("не число: {s}")),
    }
}

fn address_from_stack(e: &Value) -> Result<TonAddress> {
    let b64 = e.get(1).and_then(|x| x["bytes"].as_str()).context("в ответе нет ячейки с адресом")?;
    let root = BagOfCells::parse(&B64.decode(b64)?).map_err(|e| anyhow::anyhow!("{e}"))?.single_root().map_err(|e| anyhow::anyhow!("{e}"))?;
    root.parser().load_address().map_err(|e| anyhow::anyhow!("{e}"))
}

fn parse_tx(t: &Value) -> Option<Tx> {
    let hash = t["transaction_id"]["hash"].as_str()?.to_string();
    let time = t["utime"].as_u64()?;
    let fee = num(&t["fee"]).unwrap_or(0);
    let (inm, outs) = (&t["in_msg"], t["out_msgs"].as_array()?);
    // Входящее: у in_msg есть источник. Исходящее: сообщения в out_msgs.
    let incoming = inm["source"].as_str().is_some_and(|s| !s.is_empty());
    let (msg, peer) = if incoming { (inm, inm["source"].as_str()?) } else { (outs.first()?, outs.first()?["destination"].as_str().unwrap_or("")) };
    let nano = if incoming { num(&msg["value"]).ok()? } else { outs.iter().filter_map(|m| num(&m["value"]).ok()).sum() };
    // Текст бывает только у сообщений-комментариев; у остальных поле `message` — служебный мусор.
    let comment = if msg["msg_data"]["@type"] == "msg.dataText" { msg["msg_data"]["text"].as_str().and_then(|t| B64.decode(t).ok()).and_then(|b| String::from_utf8(b).ok()).unwrap_or_default() } else { String::new() };
    Some(Tx { time, hash, incoming, peer: peer.into(), nano, fee, comment })
}

#[cfg(test)]
mod tests {
    use std::{
        str::FromStr,
        sync::{Arc, Mutex},
    };

    use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener};

    use super::*;
    use crate::{
        tokens::{USDT_MASTER, defaults},
        wallet::{check::decode, parse_dest},
    };

    type Log = Arc<Mutex<Vec<(String, String)>>>;

    /// Поддельный сервер: отвечает по пути (без запроса) заранее заготовленным JSON, записывает (путь с запросом, тело).
    async fn mock(routes: Vec<(&'static str, String)>) -> (String, Log) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (url, log): (String, Log) = (format!("http://{}/api/v2", l.local_addr().unwrap()), Log::default());
        let lg = log.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else { return };
                let (routes, lg) = (routes.clone(), lg.clone());
                tokio::spawn(async move {
                    let mut buf = vec![];
                    let mut tmp = [0u8; 4096];
                    let (head_end, len) = loop {
                        let n = s.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&buf[..p]).to_lowercase();
                            let len = head.lines().find_map(|l| l.strip_prefix("content-length: ")).and_then(|v| v.trim().parse().ok()).unwrap_or(0usize);
                            break (p + 4, len);
                        }
                    };
                    while buf.len() < head_end + len {
                        let n = s.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                    let target = head.split_whitespace().nth(1).unwrap_or("").to_string();
                    let path = target.split('?').next().unwrap_or("").to_string();
                    let body = String::from_utf8_lossy(&buf[head_end..head_end + len]).to_string();
                    lg.lock().unwrap().push((target.clone(), body.clone()));
                    // Для runGetMethod ответ выбирается по имени метода в теле.
                    let key = if path.ends_with("runGetMethod") { format!("runGetMethod:{}", serde_json::from_str::<Value>(&body).map(|v| v["method"].as_str().unwrap_or("").to_string()).unwrap_or_default()) } else { path.rsplit('/').next().unwrap_or("").to_string() };
                    let resp = routes.iter().find(|(k, _)| *k == key).map(|(_, v)| v.clone()).unwrap_or_else(|| json!({ "ok": false, "error": format!("нет маршрута {key}") }).to_string());
                    s.write_all(format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{resp}", resp.len()).as_bytes()).await.ok();
                });
            }
        });
        (url, log)
    }

    fn fx(name: &str) -> String {
        std::fs::read_to_string(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }
    fn ok(result: Value) -> String {
        json!({ "ok": true, "result": result }).to_string()
    }
    fn run(stack: Value) -> String {
        ok(json!({ "exit_code": 0, "stack": stack }))
    }

    const WORDS: &str = "fancy carpet hello mandate penalty trial consider property top vicious exit rebuild tragic profit urban major total month holiday sudden rib gather media vicious";
    fn wallet() -> Wallet {
        use tonlib_core::wallet::mnemonic::Mnemonic;
        Wallet::from_key_pair(Mnemonic::from_str(WORDS, &None).unwrap().to_key_pair().unwrap(), Network::Mainnet).unwrap()
    }

    #[tokio::test]
    async fn real_responses_parse_balance_seqno_jetton_wallet_and_history() {
        let info: Value = serde_json::from_str(&fx("info_active.json")).unwrap();
        let bal = info["result"]["balance"].as_str().unwrap().to_string();
        let (url, _) = mock(vec![
            ("getAddressBalance", ok(json!(bal))),
            ("getAddressInformation", fx("info_active.json")),
            ("runGetMethod:seqno", run(json!([["num", "0x14c97"]]))),
            ("runGetMethod:get_wallet_address", fx("jetton_wallet_addr.json")),
            ("getTransactions", fx("txs.json")),
        ])
        .await;
        let api = Api::new(&url, None).unwrap();
        let a = TonAddress::from_str("EQDtFpEwcFAEcRe5mLVh2N6C0x-_hJEM7W61_JLnSF74p4q2").unwrap();
        assert_eq!(api.balance(&a).await.unwrap(), bal.parse::<u128>().unwrap());
        assert_eq!(api.seqno(&a).await.unwrap(), (0x14c97, true));
        let master = TonAddress::from_str(USDT_MASTER).unwrap();
        let jw = api.jetton_wallet(&master, &a).await.unwrap();
        assert_eq!(jw.workchain, 0);
        let txs = api.history(&a, 3).await.unwrap();
        assert_eq!(txs.len(), 3);
        let first = &txs[0];
        assert!(first.incoming && first.nano == 999_139_197 && first.peer == "EQA3eljtgWv" .to_string() + "fKAmcquiqZ9SWNwESnzkYRG9bIIma4xVhR4QA" && first.fee == 551_001, "{first:?}");
        assert_eq!(first.comment, "", "у не-текстового сообщения комментария нет");
    }

    #[tokio::test]
    async fn uninitialized_wallet_has_seqno_zero_and_is_not_deployed() {
        let (url, log) = mock(vec![("getAddressInformation", fx("info_uninit.json"))]).await;
        let api = Api::new(&url, None).unwrap();
        let a = TonAddress::from_str("EQCDM_QGggZ3qMa_f3lRPk4_qLDnLTqdi6OkMAV2NB9r5TG3").unwrap();
        assert_eq!(api.seqno(&a).await.unwrap(), (0, false));
        assert_eq!(log.lock().unwrap().len(), 1, "get-метод у несозданного кошелька не вызываем");
    }

    #[tokio::test]
    async fn send_ton_signs_what_was_asked_and_checks_balance_first() {
        let w = wallet();
        let to = parse_dest("EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs", Network::Mainnet).unwrap();
        let (url, log) = mock(vec![("getAddressBalance", ok(json!("5000000000"))), ("getAddressInformation", fx("info_active.json")), ("runGetMethod:seqno", run(json!([["num", "0x9"]]))), ("sendBoc", ok(json!({ "hash": "x" })))]).await;
        let api = Api::new(&url, None).unwrap();
        api.send_ton(&w, &to, 2_000_000_000, Some("за кофе"), 1_000).await.unwrap();
        let sent = log.lock().unwrap().iter().find(|(p, _)| p.ends_with("sendBoc")).map(|(_, b)| serde_json::from_str::<Value>(b).unwrap()["boc"].as_str().unwrap().to_string()).expect("sendBoc не вызван");
        let d = decode(&sent, w.public_key()).unwrap();
        assert!(d.signature_ok);
        assert_eq!((d.seqno, d.value, d.text.as_deref()), (9, 2_000_000_000, Some("за кофе")));
        assert_eq!(d.dest, to.addr);
        // Денег меньше суммы + комиссия: ничего не отправляется.
        let before = log.lock().unwrap().len();
        let e = api.send_ton(&w, &to, 4_995_000_000, None, 1_000).await.unwrap_err();
        assert!(e.to_string().contains("недостаточно TON"), "{e}");
        assert!(log.lock().unwrap()[before..].iter().all(|(p, _)| !p.ends_with("sendBoc")), "при нехватке денег отправка не должна вызываться");
    }

    #[tokio::test]
    async fn send_jetton_checks_jetton_and_gas_and_targets_jetton_wallet() {
        let w = wallet();
        let usdt = defaults(Network::Mainnet).remove(1);
        let to = parse_dest("EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs", Network::Mainnet).unwrap();
        let routes = |ton: &str, jetton: &str| {
            vec![
                ("getAddressBalance", ok(json!(ton))),
                ("getAddressInformation", fx("info_active.json")),
                ("runGetMethod:seqno", run(json!([["num", "0x2"]]))),
                ("runGetMethod:get_wallet_address", fx("jetton_wallet_addr.json")),
                ("runGetMethod:get_wallet_data", run(json!([["num", jetton]]))),
                ("sendBoc", ok(json!({}))),
            ]
        };
        let sent_count = |log: &Log| log.lock().unwrap().iter().filter(|(p, _)| p.ends_with("sendBoc")).count();
        // Всё есть: уходит перевод в кошелёк jetton'а.
        let (url, log) = mock(routes("1000000000", "0x4c4b40")).await; // 5 USDT
        let api = Api::new(&url, None).unwrap();
        api.send_jetton(&w, &usdt, &to, 5_000_000, 1_000).await.unwrap();
        let boc = log.lock().unwrap().iter().find(|(p, _)| p.ends_with("sendBoc")).map(|(_, b)| serde_json::from_str::<Value>(b).unwrap()["boc"].as_str().unwrap().to_string()).unwrap();
        let d = decode(&boc, w.public_key()).unwrap();
        assert!(d.signature_ok && d.opcode == 0x0f8a7ea5 && d.jetton_amount == Some(5_000_000) && d.jetton_dest.as_ref() == Some(&to.addr) && d.value == JETTON_GAS, "{d:?}");
        // Не хватает jetton'а.
        let (url, log) = mock(routes("1000000000", "0x1")).await;
        let e = Api::new(&url, None).unwrap().send_jetton(&w, &usdt, &to, 5_000_000, 1_000).await.unwrap_err();
        assert!(e.to_string().contains("недостаточно USDT"), "{e}");
        assert_eq!(sent_count(&log), 0);
        // Не хватает TON на газ.
        let (url, log) = mock(routes("1000", "0x4c4b40")).await;
        let e = Api::new(&url, None).unwrap().send_jetton(&w, &usdt, &to, 5_000_000, 1_000).await.unwrap_err();
        assert!(e.to_string().contains("на газ"), "{e}");
        assert_eq!(sent_count(&log), 0);
    }

    #[tokio::test]
    async fn api_errors_are_reported_and_garbage_is_not_trusted() {
        let (url, _) = mock(vec![("getAddressBalance", json!({ "ok": false, "error": "rate limit" }).to_string()), ("sendBoc", "это не json".into())]).await;
        let api = Api::new(&url, None).unwrap();
        let a = TonAddress::from_str("EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs").unwrap();
        assert!(api.balance(&a).await.unwrap_err().to_string().contains("rate limit"));
        assert!(api.send_boc("AAAA").await.is_err());
        assert!(Api::new("http://127.0.0.1:1/api/v2", None).unwrap().balance(&a).await.is_err(), "нет соединения");
    }

    /// Живой сервер: `cargo test -p rift-wallet -- --ignored live`. Нужен интернет.
    #[tokio::test]
    #[ignore]
    async fn live_mainnet_reads() {
        let api = Api::for_network(Network::Mainnet, None).unwrap();
        let a = TonAddress::from_str("EQDtFpEwcFAEcRe5mLVh2N6C0x-_hJEM7W61_JLnSF74p4q2").unwrap();
        assert!(api.balance(&a).await.unwrap() > 0);
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let master = TonAddress::from_str(USDT_MASTER).unwrap();
        let jw = api.jetton_wallet(&master, &a).await.unwrap();
        assert_eq!(jw.workchain, 0);
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let _ = api.jetton_balance(&master, &a).await.unwrap();
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(!api.history(&a, 3).await.unwrap().is_empty());
    }
}
