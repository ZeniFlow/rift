//! Кошелёк Rift: некастодиальный, ключи только на устройстве (W5). Сеть TON (W6): TON, USDT и RIFT как jetton'ы (W8).
//!
//! * [`vault`] — ключ под паролем: 24 слова TON, шифрование Argon2id + ChaCha20-Poly1305.
//! * [`wallet`] — подпись переводов (кошелёк V4R2): TON и jetton.
//! * [`api`] — чтение сети и отправка через HTTP API (toncenter-подобный). Ответам API верить нельзя: отправка подписывается локально,
//!   а чужая ложь про баланс не даёт украсть, только ввести в заблуждение (проверка перед отправкой, см. [`api::Api::send_jetton`]).
//! * [`tokens`] — список монет и точная работа с суммами (без чисел с плавающей точкой).

pub mod api;
mod http;
pub mod tokens;
pub mod vault;
pub mod wallet;

pub use tonlib_core::TonAddress;
