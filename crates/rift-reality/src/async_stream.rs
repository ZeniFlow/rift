//! Минимальная замена async_stream из shoes: только то, что нужно crypto_tls_stream.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite};

pub trait AsyncPing {
    fn supports_ping(&self) -> bool;
    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>>;
}

pub trait AsyncStream: AsyncRead + AsyncWrite + AsyncPing + Unpin + Send + Sync {}

macro_rules! plain_stream {
    ($($t:ty),*) => {$(
        impl AsyncPing for $t {
            fn supports_ping(&self) -> bool {
                false
            }
            fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
                Poll::Ready(Ok(false))
            }
        }
        impl AsyncStream for $t {}
    )*};
}

plain_stream!(tokio::net::TcpStream, tokio::io::DuplexStream);
