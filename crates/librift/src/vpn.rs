//! Mesh-VPN: IPv6-пакеты из TUN едут к нодам из списка peers в QUIC-датаграммах.
//!
//! Адрес ноды `fd72:` + первые 14 байт её публичного ключа. Подделать его — значит подобрать
//! Ed25519-ключ под 112 бит, поэтому src каждого входящего пакета сверяется с ключом соединения.

use std::{
    collections::HashMap,
    net::Ipv6Addr,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use iroh::{
    Endpoint, EndpointAddr,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::NodeId;

pub const VPN_ALPN: &[u8] = b"rift/vpn/0";
/// Минимальный MTU IPv6. Пакеты больше датаграммы уходят отдельным QUIC-стримом.
pub const MTU: u16 = 1280;
pub const PREFIX_LEN: u8 = 16;
const PREFIX: [u8; 2] = [0xfd, 0x72];

pub fn addr_of(id: &NodeId) -> Ipv6Addr {
    let mut b = [0u8; 16];
    b[..2].copy_from_slice(&PREFIX);
    b[2..].copy_from_slice(&id.as_bytes()[..14]);
    b.into()
}

/// (src, dst) IPv6-пакета, если это IPv6.
fn ipv6_src_dst(pkt: &[u8]) -> Option<(Ipv6Addr, Ipv6Addr)> {
    if pkt.len() < 40 || pkt[0] >> 4 != 6 {
        return None;
    }
    let src: [u8; 16] = pkt[8..24].try_into().ok()?;
    let dst: [u8; 16] = pkt[24..40].try_into().ok()?;
    Some((src.into(), dst.into()))
}

#[derive(Debug, Clone)]
pub struct Vpn {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    me: Ipv6Addr,
    peers: HashMap<Ipv6Addr, EndpointAddr>,
    state: Mutex<State>,
    to_tun: mpsc::Sender<Bytes>,
}

/// Соединения и очереди дозвона под одним замком: пакет не может застрять в очереди,
/// которую уже выгребли.
#[derive(Debug, Default)]
struct State {
    conns: HashMap<NodeId, Connection>,
    /// Пир, до которого идёт дозвон → пакеты, ждущие соединения.
    pending: HashMap<NodeId, Vec<Bytes>>,
}

/// Сколько пакетов держим на пира, пока дозваниваемся.
const PENDING_MAX: usize = 64;

impl Vpn {
    /// `peers` — кому разрешено с нами говорить и как до них дозвониться.
    /// `to_tun` — куда складывать пакеты, пришедшие из сети.
    pub fn new(me: NodeId, peers: Vec<EndpointAddr>, to_tun: mpsc::Sender<Bytes>) -> Self {
        let peers = peers.into_iter().map(|p| (addr_of(&p.id), p)).collect();
        Self {
            inner: Arc::new(Inner {
                me: addr_of(&me),
                peers,
                state: Default::default(),
                to_tun,
            }),
        }
    }

    pub fn addr(&self) -> Ipv6Addr {
        self.inner.me
    }

    /// Гонит пакеты из TUN в сеть, пока канал не закроется.
    pub async fn run(self, endpoint: Endpoint, mut from_tun: mpsc::Receiver<Bytes>) {
        while let Some(pkt) = from_tun.recv().await {
            self.send(&endpoint, pkt);
        }
    }

    fn send(&self, endpoint: &Endpoint, pkt: Bytes) {
        let Some((_, dst)) = ipv6_src_dst(&pkt) else { return };
        let Some(peer) = self.inner.peers.get(&dst) else { return };
        let mut state = self.inner.state.lock().unwrap();
        if let Some(conn) = state.conns.get(&peer.id) {
            send_on(conn.clone(), pkt);
            return;
        }
        if let Some(queue) = state.pending.get_mut(&peer.id) {
            if queue.len() < PENDING_MAX {
                queue.push(pkt);
            }
            return;
        }
        state.pending.insert(peer.id, vec![pkt]);
        drop(state);
        self.dial(endpoint.clone(), peer.clone());
    }

    fn dial(&self, endpoint: Endpoint, peer: EndpointAddr) {
        let this = self.clone();
        tokio::spawn(async move {
            let id = peer.id;
            match endpoint.connect(peer, VPN_ALPN).await {
                Ok(conn) => this.serve(conn).await,
                Err(e) => {
                    this.inner.state.lock().unwrap().pending.remove(&id);
                    warn!("vpn: не удалось соединиться с {}: {e}", id.fmt_short());
                }
            }
        });
    }

    /// Регистрирует соединение и принимает из него пакеты, пока оно живо.
    async fn serve(&self, conn: Connection) {
        let remote = conn.remote_id();
        let src = addr_of(&remote);
        {
            let mut state = self.inner.state.lock().unwrap();
            state.conns.insert(remote, conn.clone());
            for pkt in state.pending.remove(&remote).unwrap_or_default() {
                send_on(conn.clone(), pkt);
            }
        }
        debug!("vpn: {} подключён", remote.fmt_short());

        let datagrams = async {
            while let Ok(pkt) = conn.read_datagram().await {
                self.deliver(src, pkt).await;
            }
        };
        let streams = async {
            while let Ok(mut recv) = conn.accept_uni().await {
                if let Ok(pkt) = recv.read_to_end(u16::MAX as usize).await {
                    self.deliver(src, pkt.into()).await;
                }
            }
        };
        tokio::join!(datagrams, streams);

        let conns = &mut self.inner.state.lock().unwrap().conns;
        if conns.get(&remote).is_some_and(|c| c.stable_id() == conn.stable_id()) {
            conns.remove(&remote);
        }
        debug!("vpn: {} отключён", remote.fmt_short());
    }

    async fn deliver(&self, expected_src: Ipv6Addr, pkt: Bytes) {
        match ipv6_src_dst(&pkt) {
            Some((src, dst)) if src == expected_src && dst == self.inner.me => {
                self.inner.to_tun.send(pkt).await.ok();
            }
            _ => debug!("vpn: отброшен пакет с чужим src/dst"),
        }
    }
}

fn send_on(conn: Connection, pkt: Bytes) {
    if pkt.len() <= conn.max_datagram_size().unwrap_or(0) {
        conn.send_datagram(pkt).ok();
        return;
    }
    tokio::spawn(async move {
        if let Ok(mut s) = conn.open_uni().await {
            s.write_all(&pkt).await.ok();
            s.finish().ok();
        }
    });
}

impl ProtocolHandler for Vpn {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        if !self.inner.peers.contains_key(&addr_of(&conn.remote_id())) {
            conn.close(1u32.into(), b"not a peer");
            return Ok(());
        }
        self.serve(conn).await;
        Ok(())
    }
}

/// Создаёт TUN-интерфейс с адресом `addr` и мостит его в каналы.
/// Возвращает (имя интерфейса, пакеты из TUN, отправка в TUN). Нужны права root/администратора.
pub fn open_tun(
    addr: Ipv6Addr,
) -> std::io::Result<(String, mpsc::Receiver<Bytes>, mpsc::Sender<Bytes>)> {
    let dev = Arc::new(
        tun_rs::DeviceBuilder::new()
            .ipv6(addr, PREFIX_LEN)
            .mtu(MTU)
            .build_async()?,
    );
    let name = dev.name()?;
    let (in_tx, in_rx) = mpsc::channel(256);
    let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(256);

    let reader = dev.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match reader.recv(&mut buf).await {
                Ok(n) => {
                    if in_tx.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    warn!("tun: чтение: {e}");
                    break;
                }
            }
        }
    });
    tokio::spawn(async move {
        while let Some(pkt) = out_rx.recv().await {
            if let Err(e) = dev.send(&pkt).await {
                warn!("tun: запись: {e}");
            }
        }
    });
    Ok((name, in_rx, out_tx))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use iroh::{RelayMode, SecretKey};

    use super::*;
    use crate::{Config, Node};

    fn packet(src: Ipv6Addr, dst: Ipv6Addr, payload_len: usize) -> Bytes {
        let mut p = vec![0u8; 40 + payload_len];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        p[6] = 59; // No Next Header
        p[7] = 64;
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        p.into()
    }

    struct TestNode {
        node: Node,
        addr: Ipv6Addr,
        from_tun: mpsc::Sender<Bytes>,
        to_tun: mpsc::Receiver<Bytes>,
    }

    async fn node(key: SecretKey, peers: Vec<EndpointAddr>) -> TestNode {
        let (to_tun_tx, to_tun) = mpsc::channel(16);
        let (from_tun, from_tun_rx) = mpsc::channel(16);
        let vpn = Vpn::new(key.public(), peers, to_tun_tx);
        let addr = vpn.addr();
        let node = Node::bind(Config {
            key,
            relay_mode: RelayMode::Disabled,
            lan: false,
            proxy: None,
            relay_ca: None,
            vpn: Some(vpn.clone()),
        })
        .await
        .unwrap();
        tokio::spawn(vpn.run(node.endpoint().clone(), from_tun_rx));
        TestNode { node, addr, from_tun, to_tun }
    }

    /// Шлёт пакет, повторяя, пока не установится соединение (первые теряются при дозвоне).
    async fn send_until_delivered(from: &TestNode, to: &mut TestNode, pkt: Bytes, tries: u32) -> bool {
        for _ in 0..tries {
            from.from_tun.send(pkt.clone()).await.unwrap();
            if let Ok(Some(got)) = tokio::time::timeout(Duration::from_secs(3), to.to_tun.recv()).await {
                assert_eq!(got, pkt);
                return true;
            }
        }
        false
    }

    #[tokio::test]
    async fn mesh_delivers_small_and_large_and_rejects_strangers() {
        let (ka, kb, kc) = (SecretKey::generate(), SecretKey::generate(), SecretKey::generate());
        // Слушатель B знает A; адреса для дозвона узнаём после bind, поэтому A создаём вторым.
        let mut b = node(kb.clone(), vec![EndpointAddr::new(ka.public())]).await;
        let a = node(ka, vec![b.node.endpoint().addr()]).await;
        let c = node(kc, vec![b.node.endpoint().addr()]).await;

        let (aa, ba, ca) = (a.addr, b.addr, c.addr);
        // Первый же пакет доходит: он ждёт в очереди, пока идёт дозвон.
        assert!(send_until_delivered(&a, &mut b, packet(aa, ba, 100), 1).await);
        // Больше любой датаграммы → уходит QUIC-стримом.
        assert!(send_until_delivered(&a, &mut b, packet(aa, ba, 3000), 50).await);
        // C не в списке peers у B.
        assert!(!send_until_delivered(&c, &mut b, packet(ca, ba, 100), 1).await);
        // A подделывает src.
        assert!(!send_until_delivered(&a, &mut b, packet(ca, ba, 100), 1).await);
    }
}
