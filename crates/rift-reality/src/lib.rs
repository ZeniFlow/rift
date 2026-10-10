//! REALITY: TLS 1.3, неотличимый от соединения с чужим сайтом (SNI, сертификат, тайминги).
//!
//! Протокол и реализация перенесены из [shoes](https://github.com/cfal/shoes)
//! (MIT, © Alex Lau, см. LICENSE-shoes). Своё здесь — только `stream` (клиент/сервер поверх tokio).

#![allow(dead_code, unused_imports)]

mod async_stream;
mod buf_reader;
mod crypto;
mod reality;
mod rustls_connection_util;
mod slide_buffer;
mod stream;
mod sync_adapter;
mod util;

pub use stream::*;
