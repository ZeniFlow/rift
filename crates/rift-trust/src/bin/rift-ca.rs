//! Оффлайн-инструмент выпуска: root → control → зона → регистратор → домен → записи.
//! Ничего не знает про сеть; root-ключ держи на отдельной машине без интернета.
//!
//! ponytail: control здесь — один ключ. Порог 2-из-3 (FROST) подпишет тем же форматом, меняется только
//! способ получения подписи.

use std::{
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use clap::Parser;
use rift_trust::*;

const DAY: Time = 86_400;

#[derive(Parser)]
#[command(name = "rift-ca", version, about = "Оффлайн-выпуск сертификатов Rift")]
enum Cmd {
    /// Создать ключ (если файла нет) и напечатать публичную часть.
    Keygen { file: PathBuf },
    /// Root → control.
    Control {
        #[arg(long)] root_key: PathBuf,
        #[arg(long)] control: PublicKey,
        #[arg(long, default_value_t = 90)] days: u64,
        #[arg(short, long)] out: PathBuf,
    },
    /// Control → зона.
    Zone {
        #[arg(long)] control_key: PathBuf,
        #[arg(long)] zone: String,
        #[arg(long)] owner: PublicKey,
        #[arg(long, default_value_t = 730)] days: u64,
        #[arg(short, long)] out: PathBuf,
    },
    /// Владелец зоны → регистратор.
    Registrar {
        #[arg(long)] zone_key: PathBuf,
        #[arg(long)] zone: String,
        #[arg(long)] registrar: PublicKey,
        #[arg(long, default_value_t = 365)] days: u64,
        #[arg(short, long)] out: PathBuf,
    },
    /// Регистратор (или владелец зоны) → домен.
    Domain {
        #[arg(long)] signer_key: PathBuf,
        #[arg(long)] name: String,
        #[arg(long)] owner: PublicKey,
        #[arg(long, default_value_t = 365)] days: u64,
        #[arg(short, long)] out: PathBuf,
    },
    /// Владелец домена → записи (куда вести домен).
    Dns {
        #[arg(long)] owner_key: PathBuf,
        #[arg(long)] name: String,
        /// NodeID хоста (можно несколько).
        #[arg(long = "host")] hosts: Vec<PublicKey>,
        #[arg(long = "txt")] txt: Vec<String>,
        #[arg(long)] seq: u64,
        #[arg(long, default_value_t = 30)] days: u64,
        #[arg(short, long)] out: PathBuf,
    },
    /// Объявление control/root: takedown или отзыв.
    Notice {
        #[arg(long)] key: PathBuf,
        /// Сертификат control (control.json), если подписывает control. Без него — подпись root.
        #[arg(long)] control_cert: Option<PathBuf>,
        #[arg(long)] freeze: Option<String>,
        #[arg(long)] revoke_zone: Option<String>,
        #[arg(long)] revoke_key: Option<PublicKey>,
        #[arg(short, long)] out: PathBuf,
    },
    /// Собрать цепочку, которую хост показывает клиентам.
    Bundle {
        #[arg(long)] control: PathBuf,
        #[arg(long)] zone: PathBuf,
        #[arg(long)] registrar: Option<PathBuf>,
        #[arg(long)] domain: PathBuf,
        #[arg(long)] dns: PathBuf,
        #[arg(short, long)] out: PathBuf,
    },
    /// Проверить цепочку так, как это делает клиент.
    Verify {
        #[arg(long)] root: PublicKey,
        #[arg(long)] bundle: PathBuf,
        #[arg(long = "notice")] notices: Vec<PathBuf>,
    },
}

fn now() -> Time {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn load_key(path: &Path) -> Result<SecretKey> {
    let b = std::fs::read(path).with_context(|| format!("не удалось прочитать {}", path.display()))?;
    let b: [u8; 32] = b.try_into().map_err(|_| anyhow::anyhow!("{}: ключ должен быть 32 байта", path.display()))?;
    Ok(SecretKey::from_bytes(&b))
}

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    from_json(&std::fs::read_to_string(path).with_context(|| format!("не удалось прочитать {}", path.display()))?)
        .with_context(|| format!("{}: не тот формат", path.display()))
}

/// Подписывает и пишет; существующий файл не перезаписывает.
fn issue<T: Kind + serde::Serialize>(body: T, key: &Path, out: &Path) -> Result<()> {
    write_new(out, &to_json(&Signed::sign(body, &load_key(key)?)))
}

fn write_new(out: &Path, text: &str) -> Result<()> {
    std::fs::OpenOptions::new().write(true).create_new(true).open(out)
        .with_context(|| format!("{} уже существует или недоступен", out.display()))?
        .write_all(text.as_bytes())?;
    println!("{}", out.display());
    Ok(())
}

fn main() -> Result<()> {
    match Cmd::parse() {
        Cmd::Keygen { file } => {
            if !file.exists() {
                let mut opts = std::fs::OpenOptions::new();
                opts.write(true).create_new(true);
                #[cfg(unix)]
                std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
                opts.open(&file)?.write_all(&SecretKey::generate().to_bytes())?;
            }
            println!("{}", load_key(&file)?.public());
        }
        Cmd::Control { root_key, control, days, out } => {
            let t = now();
            issue(ControlCert { key: control, issued_at: t, expires_at: t + days * DAY }, &root_key, &out)?
        }
        Cmd::Zone { control_key, zone, owner, days, out } => {
            if !valid_label(&zone) {
                bail!("недопустимое имя зоны: {zone}");
            }
            let t = now();
            issue(ZoneCert { zone, owner, issued_at: t, expires_at: t + days * DAY }, &control_key, &out)?
        }
        Cmd::Registrar { zone_key, zone, registrar, days, out } => {
            let t = now();
            issue(RegistrarCert { zone, registrar, issued_at: t, expires_at: t + days * DAY }, &zone_key, &out)?
        }
        Cmd::Domain { signer_key, name, owner, days, out } => {
            if split_name(&name).is_none() {
                bail!("недопустимое имя: {name} (нужно <метка>.<зона>, a-z 0-9 -)");
            }
            let t = now();
            issue(DomainRecord { name, owner, issued_at: t, expires_at: t + days * DAY }, &signer_key, &out)?
        }
        Cmd::Dns { owner_key, name, hosts, txt, seq, days, out } => {
            let t = now();
            let records = hosts.into_iter().map(Record::Host).chain(txt.into_iter().map(Record::Txt)).collect();
            issue(DnsRecords { name, seq, records, issued_at: t, expires_at: t + days * DAY }, &owner_key, &out)?
        }
        Cmd::Notice { key, control_cert, freeze, revoke_zone, revoke_key, out } => {
            let since = now();
            let n = match (freeze, revoke_zone, revoke_key) {
                (Some(name), None, None) => Notice::Freeze { name, since },
                (None, Some(zone), None) => Notice::RevokeZone { zone, since },
                (None, None, Some(key)) => Notice::RevokeKey { key, since },
                _ => bail!("нужен ровно один из --freeze / --revoke-zone / --revoke-key"),
            };
            let a = Announcement {
                notice: Signed::sign(n, &load_key(&key)?),
                control: control_cert.as_deref().map(read).transpose()?,
            };
            write_new(&out, &to_json(&a))?
        }
        Cmd::Bundle { control, zone, registrar, domain, dns, out } => {
            let b = Bundle {
                control: read(&control)?,
                zone: read(&zone)?,
                registrar: registrar.as_deref().map(read).transpose()?,
                domain: read(&domain)?,
                dns: read(&dns)?,
            };
            write_new(&out, &to_json(&b))?
        }
        Cmd::Verify { root, bundle, notices } => {
            let notices = notices.iter().map(|p| read(p)).collect::<Result<Vec<_>>>()?;
            let r = verify(&root, &read(&bundle)?, &notices, now())?;
            println!("OK  {}\nвладелец: {}\nseq:      {}", r.name, r.owner, r.seq);
            for h in r.hosts {
                println!("host:     {h}");
            }
            for t in r.txt {
                println!("txt:      {t}");
            }
        }
    }
    Ok(())
}
