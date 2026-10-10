//! Сетевые логи и свидетели (trust.md §3).
//!
//! * **Лог** — нода, чей ключ = ключ лога (NodeID и есть ключ, поэтому лог находят по NodeID).
//!   Добавлять записи могут только явно разрешённые ноды (`appenders`). Он подписывает головы,
//!   сам приносит их свидетелям и хранит подписи; по запросу отдаёт доказательство от
//!   САМОЙ РАННЕЙ головы с кворумом подписей (для отзыва ключей важно, как рано запись доказуемо в логе).
//! * **Свидетель** — пассивная нода: проверяет голову по своему состоянию и подписывает. Если ему нужно
//!   доказательство согласованности, он так и отвечает, лог присылает его повторным запросом.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use iroh::{
    Endpoint, EndpointAddr,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use rift_trust::{
    PublicKey, SecretKey, Signed,
    log::{Cosig, Log, Proof, TreeHead, Witness, check_entry_format},
    merkle::Hash,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::sync::Notify;
use tracing::{debug, warn};

use crate::names::now;

pub const LOG_ALPN: &[u8] = b"rift/log/0";
pub const WITNESS_ALPN: &[u8] = b"rift/witness/0";
const MAX_MSG: usize = 512 * 1024;
const MAX_ENTRY: usize = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(10);
/// Как часто лог перепроверяет, не осталось ли голов без подписей свидетелей.
const RETRY: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------- транспорт

pub(crate) async fn rpc<Q: Serialize, A: DeserializeOwned>(endpoint: &Endpoint, to: impl Into<EndpointAddr>, alpn: &[u8], q: &Q) -> Result<A> {
    let exchange = async {
        let conn = endpoint.connect(to, alpn).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_all(&serde_json::to_vec(q)?).await?;
        send.finish()?;
        let bytes = recv.read_to_end(MAX_MSG).await?;
        conn.close(0u32.into(), b"bye");
        anyhow::Ok(serde_json::from_slice(&bytes)?)
    };
    tokio::time::timeout(TIMEOUT, exchange).await.map_err(|_| anyhow!("нет ответа за {TIMEOUT:?}"))?
}

async fn respond<Q: DeserializeOwned, A: Serialize>(conn: &Connection, f: impl FnOnce(Result<Q, String>) -> A) {
    let Ok((mut send, mut recv)) = conn.accept_bi().await else { return };
    let Ok(bytes) = recv.read_to_end(MAX_MSG).await else { return };
    let a = f(serde_json::from_slice(&bytes).map_err(|e| format!("не разобрал запрос: {e}")));
    if send.write_all(&serde_json::to_vec(&a).expect("сериализуется")).await.is_ok() {
        send.finish().ok();
        conn.closed().await; // ждём клиента: иначе ответ может не дойти
    }
}

fn save_json<T: Serialize>(path: &Path, v: &T) -> std::io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(v)?)?;
    std::fs::rename(tmp, path)
}

fn load_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match std::fs::read(path) {
        Ok(b) => Ok(Some(serde_json::from_slice(&b).with_context(|| format!("{}: повреждён", path.display()))?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("не удалось прочитать {}", path.display())),
    }
}

// ---------------------------------------------------------------- протокол лога

#[derive(Debug, Serialize, Deserialize)]
pub enum LogRequest {
    /// Только для разрешённых нод.
    Append { entry: String },
    /// Доказательство от самой ранней головы с кворумом подписей.
    Prove { index: u64 },
    Consistency { old: u64, new: u64 },
    Head,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum LogResponse {
    Appended { index: u64, size: u64 },
    Proof(Proof),
    Consistency(Vec<Hash>),
    Head(Signed<TreeHead>),
    Err(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HeadRec {
    head: Signed<TreeHead>,
    cosigs: Vec<Cosig>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct LogState {
    log: Log,
    heads: Vec<HeadRec>,
}

#[derive(Debug)]
struct LogInner {
    key: SecretKey,
    appenders: Vec<PublicKey>,
    quorum: usize,
    path: Option<PathBuf>,
    state: Mutex<LogState>,
    wake: Notify,
}

#[derive(Debug, Clone)]
pub struct LogService {
    inner: Arc<LogInner>,
}

impl LogService {
    /// `key` — ключ лога (им подписываются головы); `appenders` — NodeID нод, которым можно добавлять записи
    /// (отдельный ключ: нода с ключом самого лога не может подключиться к логу — iroh не соединяет ноду с собой);
    /// `quorum` — сколько подписей свидетелей нужно голове, чтобы по ней выдавать доказательства.
    // ponytail: дерево пересчитывается с нуля на каждое доказательство, O(n); хватит до ~10^5 записей.
    pub fn new(key: SecretKey, path: Option<PathBuf>, appenders: Vec<PublicKey>, quorum: usize) -> Result<Self> {
        let state: LogState = match &path {
            Some(p) => load_json(p)?.unwrap_or_default(),
            None => LogState::default(),
        };
        // Не стартуем на повреждённом или подменённом файле: иначе лог молча «забудет» то, что подписывал.
        for r in &state.heads {
            if r.head.body.log != key.public() || !r.head.verify(&key.public()) {
                bail!("файл лога: голова подписана не этим ключом (чужой файл?)");
            }
            if state.log.root_at(r.head.body.size) != Some(r.head.body.root) {
                bail!("файл лога повреждён: записи не сходятся с подписанной головой размера {}", r.head.body.size);
            }
        }
        if let Some(p) = &path {
            // Лог, который не может сохранить состояние, забудет подписанное при рестарте: лучше не стартовать.
            save_json(p, &state).with_context(|| format!("нельзя записать {}", p.display()))?;
        }
        Ok(Self { inner: Arc::new(LogInner { key, appenders, quorum, path, state: Mutex::new(state), wake: Notify::new() }) })
    }

    fn save(&self, st: &LogState) -> std::io::Result<()> {
        match &self.inner.path {
            Some(p) => save_json(p, st),
            None => Ok(()),
        }
    }

    pub fn handle(&self, from: PublicKey, req: LogRequest) -> LogResponse {
        let inner = &self.inner;
        let mut st = inner.state.lock().unwrap();
        match req {
            LogRequest::Append { entry } => {
                if !inner.appenders.contains(&from) {
                    return LogResponse::Err("добавлять записи не разрешено этой ноде".into());
                }
                if entry.len() > MAX_ENTRY {
                    return LogResponse::Err("запись слишком большая".into());
                }
                if let Err(e) = check_entry_format(&entry) {
                    return LogResponse::Err(e);
                }
                let index = match st.log.entries.iter().position(|e| *e == entry) {
                    Some(i) => i as u64, // повтор безвреден
                    None => {
                        let i = st.log.append(entry);
                        if let Err(e) = self.save(&st) {
                            // Не подтверждаем запись, которую не смогли сохранить.
                            st.log.entries.pop();
                            return LogResponse::Err(format!("не удалось сохранить лог: {e}"));
                        }
                        inner.wake.notify_one();
                        i
                    }
                };
                LogResponse::Appended { index, size: st.log.len() }
            }
            LogRequest::Prove { index } => {
                let rec = st.heads.iter().find(|r| r.head.body.size > index && r.cosigs.len() >= inner.quorum);
                match rec.and_then(|r| st.log.prove(index, &r.head, r.cosigs.clone())) {
                    Some(p) => LogResponse::Proof(p),
                    None if index >= st.log.len() => LogResponse::Err("такой записи нет".into()),
                    None => LogResponse::Err("голова с подписями свидетелей ещё не готова, повтори позже".into()),
                }
            }
            LogRequest::Consistency { old, new } => match st.log.consistency(old, new) {
                Some(p) => LogResponse::Consistency(p),
                None => LogResponse::Err("нет такого диапазона".into()),
            },
            LogRequest::Head => match st.heads.last() {
                Some(r) => LogResponse::Head(r.head.clone()),
                None => LogResponse::Err("лог пуст".into()),
            },
        }
    }

    /// Фоновая работа: подписывать новые головы и собирать подписи свидетелей. Крутится, пока жива нода.
    pub async fn run(&self, endpoint: Endpoint, witnesses: Vec<EndpointAddr>) {
        loop {
            self.step(&endpoint, &witnesses).await;
            tokio::select! {
                _ = self.inner.wake.notified() => {}
                _ = tokio::time::sleep(RETRY) => {}
            }
        }
    }

    async fn step(&self, endpoint: &Endpoint, witnesses: &[EndpointAddr]) {
        // Голова на текущий размер. Подписываем только последнюю: свидетель не принимает старые после новых.
        let head = {
            let mut st = self.inner.state.lock().unwrap();
            if st.log.is_empty() {
                return;
            }
            if st.heads.last().is_none_or(|r| r.head.body.size != st.log.len()) {
                let head = st.log.head(&self.inner.key, now());
                st.heads.push(HeadRec { head, cosigs: vec![] });
                if let Err(e) = self.save(&st) {
                    warn!("лог: голова не сохранена: {e}"); // повторится на следующем шаге; подписанная голова не противоречит ничему
                }
            }
            st.heads.last().unwrap().head.clone()
        };
        for w in witnesses {
            let have = |st: &LogState| st.heads.last().is_some_and(|r| r.cosigs.iter().any(|c| c.witness == w.id));
            if have(&self.inner.state.lock().unwrap()) {
                continue;
            }
            match self.cosign_via(endpoint, w, &head).await {
                Ok(c) => {
                    let mut st = self.inner.state.lock().unwrap();
                    let last = st.heads.last_mut().unwrap();
                    // Голова могла устареть, пока ждали ответ: тогда подпись достанется ей же.
                    if last.head.body.size == head.body.size && !last.cosigs.iter().any(|x| x.witness == c.witness) {
                        last.cosigs.push(c);
                        if let Err(e) = self.save(&st) {
                            warn!("лог: подписи не сохранены: {e}");
                        }
                    }
                }
                Err(e) => warn!("свидетель {}: {e:#}", w.id.fmt_short()),
            }
        }
        // Пришли новые записи, пока ходили к свидетелям.
        let st = self.inner.state.lock().unwrap();
        if st.heads.last().is_some_and(|r| r.head.body.size != st.log.len()) {
            self.inner.wake.notify_one();
        }
    }

    async fn cosign_via(&self, endpoint: &Endpoint, w: &EndpointAddr, head: &Signed<TreeHead>) -> Result<Cosig> {
        let ask = async |consistency: Vec<Hash>| {
            let req = WitnessRequest::Cosign { head: head.clone(), consistency };
            rpc::<_, WitnessResponse>(endpoint, w.clone(), WITNESS_ALPN, &req).await
        };
        let got = match ask(vec![]).await? {
            WitnessResponse::NeedConsistency { from } => {
                let proof = self
                    .inner
                    .state
                    .lock()
                    .unwrap()
                    .log
                    .consistency(from, head.body.size)
                    .ok_or_else(|| anyhow!("свидетель видел размер {from}, а у меня такого нет"))?;
                ask(proof).await?
            }
            other => other,
        };
        match got {
            WitnessResponse::Cosig(c) if c.witness == w.id && c.valid(head) => Ok(c),
            WitnessResponse::Cosig(_) => bail!("подпись свидетеля не сходится с его NodeID или с головой"),
            WitnessResponse::NeedConsistency { .. } => bail!("свидетель просит доказательство повторно"),
            WitnessResponse::Refused(why) => bail!("отказал: {why}"),
        }
    }
}

impl ProtocolHandler for LogService {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let from = conn.remote_id();
        respond(&conn, |q| match q {
            Ok(q) => self.handle(from, q),
            Err(e) => LogResponse::Err(e),
        })
        .await;
        Ok(())
    }
}

// ---------------------------------------------------------------- протокол свидетеля

#[derive(Debug, Serialize, Deserialize)]
pub enum WitnessRequest {
    Cosign { head: Signed<TreeHead>, consistency: Vec<Hash> },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WitnessResponse {
    Cosig(Cosig),
    /// Доказательство согласованности с размера `from` до этой головы.
    NeedConsistency { from: u64 },
    Refused(String),
}

#[derive(Debug)]
struct WitnessInner {
    key: SecretKey,
    /// Какие логи подписываем. Пусто — любые (тогда состояние растёт с числом логов).
    allowed: Vec<PublicKey>,
    path: Option<PathBuf>,
    state: Mutex<Witness>,
}

#[derive(Debug, Clone)]
pub struct WitnessService {
    inner: Arc<WitnessInner>,
}

impl WitnessService {
    pub fn new(key: SecretKey, path: Option<PathBuf>, allowed: Vec<PublicKey>) -> Result<Self> {
        let state = match &path {
            Some(p) => load_json(p)?.unwrap_or_default(),
            None => Witness::default(),
        };
        if let Some(p) = &path {
            save_json(p, &state).with_context(|| format!("нельзя записать {}", p.display()))?;
        }
        Ok(Self { inner: Arc::new(WitnessInner { key, allowed, path, state: Mutex::new(state) }) })
    }

    pub fn handle(&self, req: WitnessRequest) -> WitnessResponse {
        let WitnessRequest::Cosign { head, consistency } = req;
        let inner = &self.inner;
        if !inner.allowed.is_empty() && !inner.allowed.contains(&head.body.log) {
            return WitnessResponse::Refused("этот лог мне не поручен".into());
        }
        let mut st = inner.state.lock().unwrap();
        if consistency.is_empty() {
            if let Some(from) = st.needs_proof(&head) {
                return WitnessResponse::NeedConsistency { from };
            }
        }
        match st.cosign(&inner.key, &head, &consistency, now()) {
            Ok(c) => {
                if let Some(p) = &inner.path {
                    if let Err(e) = save_json(p, &*st) {
                        // Без сохранённого состояния после рестарта свидетель забудет виденное — это дыра. Не подписываем.
                        return WitnessResponse::Refused(format!("не удалось сохранить состояние: {e}"));
                    }
                }
                debug!("свидетель подписал {} размера {}", head.body.log.fmt_short(), head.body.size);
                WitnessResponse::Cosig(c)
            }
            Err(e) => WitnessResponse::Refused(e.to_string()),
        }
    }
}

impl ProtocolHandler for WitnessService {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        respond(&conn, |q| match q {
            Ok(q) => self.handle(q),
            Err(e) => WitnessResponse::Refused(e),
        })
        .await;
        Ok(())
    }
}

// ---------------------------------------------------------------- клиент

/// Добавляет запись. Возвращает (индекс, размер лога).
pub async fn append(endpoint: &Endpoint, log: impl Into<EndpointAddr>, entry: String) -> Result<(u64, u64)> {
    match rpc(endpoint, log, LOG_ALPN, &LogRequest::Append { entry }).await? {
        LogResponse::Appended { index, size } => Ok((index, size)),
        LogResponse::Err(e) => bail!("{e}"),
        other => bail!("неожиданный ответ лога: {other:?}"),
    }
}

/// Доказательство включения. Пока свидетели не подписали голову, лог отвечает «повтори позже»: ждём до `wait`.
pub async fn prove(endpoint: &Endpoint, log: impl Into<EndpointAddr> + Clone, index: u64, wait: Duration) -> Result<Proof> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        match rpc(endpoint, log.clone(), LOG_ALPN, &LogRequest::Prove { index }).await? {
            LogResponse::Proof(p) => return Ok(p),
            LogResponse::Err(e) if e.contains("повтори позже") && tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            LogResponse::Err(e) => bail!("{e}"),
            other => bail!("неожиданный ответ лога: {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use iroh::RelayMode;
    use rift_trust::{Trust, ZoneCert, log::{check_proof, entry_of}};

    use super::*;
    use crate::{Config, Handler, Node};

    async fn node(key: SecretKey, extra: Vec<(Vec<u8>, Handler)>) -> Node {
        Node::bind(Config {
            key,
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

    fn zone_entry(n: u32) -> String {
        let cert = ZoneCert { zone: format!("z{n}"), owner: SecretKey::generate().public(), issued_at: 0, expires_at: 1 };
        entry_of(&Signed::sign(cert, &SecretKey::generate()))
    }

    struct Net {
        log_key: SecretKey,
        svc: LogService,
        log: Node,
        witnesses: Vec<(WitnessService, Node)>,
        client: Node,
        trust: Trust,
    }

    /// Лог + два свидетеля + клиент, которому разрешено добавлять.
    async fn net() -> Net {
        let log_key = SecretKey::generate();
        let client = node(SecretKey::generate(), vec![]).await;
        let svc = LogService::new(log_key.clone(), None, vec![client.id()], 2).unwrap();
        let log = node(log_key.clone(), vec![(LOG_ALPN.to_vec(), Box::new(svc.clone()))]).await;
        let mut witnesses = vec![];
        for _ in 0..2 {
            let ws = WitnessService::new(SecretKey::generate(), None, vec![]).unwrap();
            let key = ws.inner.key.clone();
            witnesses.push((ws.clone(), node(key, vec![(WITNESS_ALPN.to_vec(), Box::new(ws))]).await));
        }
        let addrs = witnesses.iter().map(|(_, n)| n.endpoint().addr()).collect();
        let (s, e) = (svc.clone(), log.endpoint().clone());
        tokio::spawn(async move { s.run(e, addrs).await });
        let trust = Trust {
            root: SecretKey::generate().public(),
            witnesses: witnesses.iter().map(|(_, n)| n.id()).collect(),
            threshold: 2,
        };
        Net { log_key, svc, log, witnesses, client, trust }
    }

    const WAIT: Duration = Duration::from_secs(10);

    #[tokio::test]
    async fn append_prove_and_growth_with_consistency() {
        let n = net().await;
        let (ep, la) = (n.client.endpoint(), n.log.endpoint().addr());

        let e0 = zone_entry(0);
        assert_eq!(append(ep, la.clone(), e0.clone()).await.unwrap(), (0, 1));
        let p0 = prove(ep, la.clone(), 0, WAIT).await.unwrap();
        check_proof(&e0, &p0, &n.log_key.public(), &n.trust, "зона").unwrap();
        assert_eq!(p0.head.body.size, 1);

        // Второй рост: свидетели уже видели размер 1 и просят доказательство согласованности.
        let e1 = zone_entry(1);
        assert_eq!(append(ep, la.clone(), e1.clone()).await.unwrap(), (1, 2));
        let p1 = prove(ep, la.clone(), 1, WAIT).await.unwrap();
        check_proof(&e1, &p1, &n.log_key.public(), &n.trust, "зона").unwrap();
        assert_eq!(p1.head.body.size, 2);
        for (w, _) in &n.witnesses {
            assert_eq!(w.inner.state.lock().unwrap().size_of(&n.log_key.public()), 2);
        }

        // Для первой записи по-прежнему отдаётся САМАЯ РАННЯЯ голова (важно для отзыва ключей).
        let again = prove(ep, la, 0, WAIT).await.unwrap();
        assert_eq!(again.head.body.size, 1);
        check_proof(&e0, &again, &n.log_key.public(), &n.trust, "зона").unwrap();
    }

    #[tokio::test]
    async fn append_rights_format_and_idempotence() {
        let n = net().await;
        let la = n.log.endpoint().addr();
        // Посторонний.
        let stranger = node(SecretKey::generate(), vec![]).await;
        let err = append(stranger.endpoint(), la.clone(), zone_entry(0)).await.unwrap_err();
        assert!(err.to_string().contains("не разрешено"), "{err}");
        // Мусор и неизвестный вид.
        for bad in ["garbage", "zone\n{}", "bogus\n{}"] {
            assert!(append(n.client.endpoint(), la.clone(), bad.into()).await.is_err(), "{bad}");
        }
        // Повтор той же записи — тот же индекс, размер не растёт.
        let e = zone_entry(7);
        let first = append(n.client.endpoint(), la.clone(), e.clone()).await.unwrap();
        assert_eq!(append(n.client.endpoint(), la.clone(), e).await.unwrap(), first);
    }

    #[tokio::test]
    async fn witnesses_refuse_a_rewritten_log() {
        let n = net().await;
        let (ep, la) = (n.client.endpoint(), n.log.endpoint().addr());
        append(ep, la.clone(), zone_entry(0)).await.unwrap();
        prove(ep, la.clone(), 0, WAIT).await.unwrap(); // честная голова размера 1 подписана обоими

        // Оператор лога тайно подменяет запись 0 и продолжает как ни в чём не бывало.
        n.svc.inner.state.lock().unwrap().log.entries[0] = zone_entry(99);
        append(ep, la.clone(), zone_entry(1)).await.unwrap();
        let err = prove(ep, la, 1, Duration::from_secs(3)).await.unwrap_err();
        assert!(err.to_string().contains("не готова"), "{err}");
        for (w, _) in &n.witnesses {
            assert_eq!(w.inner.state.lock().unwrap().size_of(&n.log_key.public()), 1, "свидетель не должен принять переписанную историю");
        }
    }

    #[test]
    fn witness_allowlist_and_persistence() {
        let dir = std::env::temp_dir().join(format!("rift-wit-{}-{}", std::process::id(), now()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("w.json");
        let (wk, lk) = (SecretKey::generate(), SecretKey::generate());
        let mut log = Log::default();
        log.append(zone_entry(0));
        let head = log.head(&lk, now());
        let ask = |w: &WitnessService, h: &Signed<TreeHead>| w.handle(WitnessRequest::Cosign { head: h.clone(), consistency: vec![] });

        // Не из списка — отказ.
        let picky = WitnessService::new(wk.clone(), None, vec![SecretKey::generate().public()]).unwrap();
        assert!(matches!(ask(&picky, &head), WitnessResponse::Refused(_)));

        // Подписал и сохранил; после «перезапуска» помнит.
        let w = WitnessService::new(wk.clone(), Some(path.clone()), vec![lk.public()]).unwrap();
        assert!(matches!(ask(&w, &head), WitnessResponse::Cosig(c) if c.witness == wk.public()));
        let w2 = WitnessService::new(wk.clone(), Some(path), vec![lk.public()]).unwrap();
        assert_eq!(w2.inner.state.lock().unwrap().size_of(&lk.public()), 1);

        // Рост без доказательства → просит его; с правильным → подписывает.
        log.append(zone_entry(1));
        let head2 = log.head(&lk, now());
        assert!(matches!(ask(&w2, &head2), WitnessResponse::NeedConsistency { from: 1 }));
        let proof = log.consistency(1, 2).unwrap();
        assert!(matches!(w2.handle(WitnessRequest::Cosign { head: head2.clone(), consistency: proof }), WitnessResponse::Cosig(_)));
        // Неправильное доказательство → отказ.
        let bogus = Log { entries: vec![zone_entry(5), zone_entry(6)] }.consistency(1, 2).unwrap();
        let w3 = WitnessService::new(wk, None, vec![]).unwrap();
        assert!(matches!(ask(&w3, &head), WitnessResponse::Cosig(_)));
        assert!(matches!(w3.handle(WitnessRequest::Cosign { head: head2, consistency: bogus }), WitnessResponse::Refused(_)));
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn log_file_is_checked_on_load() {
        let dir = std::env::temp_dir().join(format!("rift-log-{}-{}", std::process::id(), now()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("log.json");
        let key = SecretKey::generate();
        let appender = SecretKey::generate().public();
        let svc = LogService::new(key.clone(), Some(path.clone()), vec![appender], 0).unwrap();
        assert!(matches!(svc.handle(appender, LogRequest::Append { entry: zone_entry(0) }), LogResponse::Appended { .. }));
        assert!(matches!(svc.handle(key.public(), LogRequest::Append { entry: zone_entry(1) }), LogResponse::Err(_)));
        let helper = node(SecretKey::generate(), vec![]).await;
        svc.step(helper.endpoint(), &[]).await; // подписывает голову и сохраняет файл

        assert!(LogService::new(key.clone(), Some(path.clone()), vec![], 0).is_ok());
        // Файл другого лога.
        assert!(LogService::new(SecretKey::generate(), Some(path.clone()), vec![], 0).is_err());
        // Записи подменили, голова осталась.
        let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        v["log"]["entries"][0] = serde_json::Value::String(zone_entry(5));
        std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
        let err = LogService::new(key, Some(path), vec![], 0).unwrap_err();
        assert!(err.to_string().contains("повреждён"), "{err}");
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn state_dir_is_created_and_unwritable_path_fails_fast() {
        let base = std::env::temp_dir().join(format!("rift-dir-{}-{}", std::process::id(), now()));
        let (appender, key) = (SecretKey::generate().public(), SecretKey::generate());
        // Каталога ещё нет (так бывает при --key: --home никто не создаёт).
        let path = base.join("nested/log.json");
        let svc = LogService::new(key.clone(), Some(path.clone()), vec![appender], 0).unwrap();
        assert!(path.exists());
        assert!(matches!(svc.handle(appender, LogRequest::Append { entry: zone_entry(0) }), LogResponse::Appended { index: 0, .. }));
        assert!(WitnessService::new(SecretKey::generate(), Some(base.join("other/w.json")), vec![]).is_ok());
        assert!(base.join("other/w.json").exists());

        // Путь, который создать нельзя (родитель — файл): не стартуем.
        let file = base.join("plain");
        std::fs::write(&file, "x").unwrap();
        assert!(LogService::new(key.clone(), Some(file.join("log.json")), vec![], 0).is_err());
        assert!(WitnessService::new(SecretKey::generate(), Some(file.join("w.json")), vec![]).is_err());

        // Запись, которую сохранить не удалось, не подтверждается и не остаётся в логе.
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap(); // на месте файла каталог → rename упадёт
        assert!(matches!(svc.handle(appender, LogRequest::Append { entry: zone_entry(1) }), LogResponse::Err(_)));
        assert_eq!(svc.inner.state.lock().unwrap().log.len(), 1, "неподтверждённая запись должна откатиться");
        std::fs::remove_dir_all(base).ok();
    }
}
