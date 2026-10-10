//! Общие помощники для тестов: цепочка доверия, свидетель, голые ноды.

use std::sync::Arc;

use iroh::SecretKey;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use crate::{
    Node,
    client::RiftClient,
    host::{HTTP_ALPN, Host},
    names::{NAMES_ALPN, NoticeCache, Request as NamesRequest, Resolver, publish},
};

#[allow(unused_imports)]
pub use crate::devnet::{DAY, bundle, node, trust, witness};

/// Приложение по умолчанию: на любой запрос отвечает `hello <путь>`.
pub async fn hello_app() -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let n = c.read(&mut buf).await.unwrap_or(0);
                let path = String::from_utf8_lossy(&buf[..n]).split_whitespace().nth(1).unwrap_or("?").to_string();
                let body = format!("hello {path}");
                c.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.ok();
            });
        }
    });
    addr
}

/// Сайт `shop.brand` за хостом (прокси на `upstream`), резолвер с его цепочкой и клиент.
#[allow(dead_code)] // `host` и `client_node` держат ноды живыми
pub struct Site {
    pub client: Arc<RiftClient>,
    pub resolver_node: Node,
    pub resolver: Resolver,
    pub root: SecretKey,
    pub host: Node,
    pub client_node: Node,
}

pub async fn site(upstream: &str) -> Site {
    let k = SecretKey::generate;
    let (root, control, zone, owner) = (k(), k(), k(), k());
    let host = node(vec![(HTTP_ALPN.to_vec(), Box::new(Host::proxy(upstream, false).unwrap()))]).await;
    let resolver = Resolver::new(trust(&root));
    let resolver_node = node(vec![(NAMES_ALPN.to_vec(), Box::new(resolver.clone()))]).await;
    let b = bundle(&root, &control, &zone, &owner, host.id(), 1);
    assert_eq!(publish(host.endpoint(), &[resolver_node.endpoint().addr()], NamesRequest::PutBundle(b)).await, 1);

    let client_node = node(vec![]).await;
    let client = Arc::new(RiftClient::new(client_node.endpoint().clone(), trust(&root), vec![resolver_node.endpoint().addr()], None, NoticeCache::memory()));
    client.add_hint(host.endpoint().addr());
    Site { client, resolver_node, resolver, root, host, client_node }
}

/// Приложение-«зеркало» для проверки шлюза: по пути отдаёт заголовки, cookie, редиректы, CSP и апгрейд.
pub async fn echo_app() -> String {
    use std::convert::Infallible;

    use http_body_util::{BodyExt, Full, combinators::BoxBody};
    use hyper::{Request, Response, StatusCode, body::Incoming, service::service_fn, upgrade};
    use hyper_util::rt::TokioIo;

    type B = BoxBody<bytes::Bytes, Infallible>;
    fn full(s: impl Into<bytes::Bytes>) -> B {
        Full::new(s.into()).boxed()
    }
    fn hv(r: &Request<Incoming>, n: &str) -> String {
        r.headers().get(n).and_then(|v| v.to_str().ok()).unwrap_or("-").to_string()
    }

    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = l.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(|mut r: Request<Incoming>| async move {
                    let path = r.uri().path().to_string();
                    let mut resp = Response::new(full(format!("hello {path}")));
                    match path.as_str() {
                        "/headers" => {
                            *resp.body_mut() = full(format!(
                                "path={} host={} xfh={} origin={} referer={} cookie={}",
                                r.uri(), hv(&r, "host"), hv(&r, "x-forwarded-host"), hv(&r, "origin"), hv(&r, "referer"), hv(&r, "cookie")
                            ));
                        }
                        "/cookie" => {
                            resp.headers_mut().append("set-cookie", "sid=1; Domain=shop.brand; Path=/; HttpOnly".parse().unwrap());
                            resp.headers_mut().append("set-cookie", "theme=dark; Path=/; Domain=.shop.brand; SameSite=Lax".parse().unwrap());
                        }
                        "/redir" | "/redir-other" => {
                            *resp.status_mut() = StatusCode::FOUND;
                            let loc = if path == "/redir" { "https://shop.brand/landing?a=1" } else { "https://shop.brand.evil.com/x" };
                            resp.headers_mut().insert("location", loc.parse().unwrap());
                        }
                        "/csp" => {
                            resp.headers_mut().insert("content-security-policy", "default-src 'self'; upgrade-insecure-requests".parse().unwrap());
                            resp.headers_mut().insert("strict-transport-security", "max-age=63072000".parse().unwrap());
                        }
                        "/ws" if r.headers().get("upgrade").is_some_and(|v| v == "echo") => {
                            let on = upgrade::on(&mut r);
                            tokio::spawn(async move {
                                let mut io = TokioIo::new(on.await.unwrap());
                                let mut buf = [0u8; 64];
                                while let Ok(n) = io.read(&mut buf).await {
                                    if n == 0 || io.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                            });
                            *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                            resp.headers_mut().insert("connection", "upgrade".parse().unwrap());
                            resp.headers_mut().insert("upgrade", "echo".parse().unwrap());
                        }
                        _ => {}
                    }
                    Ok::<_, Infallible>(resp)
                });
                hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tcp), svc).with_upgrades().await.ok();
            });
        }
    });
    addr
}
