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

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, ValueEnum};
use rift_trust::log::{Cosig, Log, Proof, TreeHead, Witness, entry_of};
use rift_trust::*;

const DAY: Time = 86_400;

#[derive(Clone, ValueEnum)]
enum EntryKind {
    Zone,
    Registrar,
    Domain,
}

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
    /// Положить выданный сертификат в лог (файл лога создаётся при первой записи; повтор безвреден).
    LogAdd {
        #[arg(long)] log: PathBuf,
        #[arg(long)] kind: EntryKind,
        #[arg(long)] cert: PathBuf,
    },
    /// Подписать голову лога: размер, корень, время. Каждая голова — новый файл.
    LogHead {
        #[arg(long)] log: PathBuf,
        /// Ключ лога = ключ выпускающего (control для зон, владелец зоны для доменов).
        #[arg(long)] key: PathBuf,
        #[arg(short, long)] out: PathBuf,
    },
    /// Свидетель: проверить, что голова честно продолжает виденное, и подписать.
    Cosign {
        #[arg(long)] witness_key: PathBuf,
        /// Состояние свидетеля (что он видел); создаётся при первом запуске.
        #[arg(long)] state: PathBuf,
        /// Копия лога, откуда берётся доказательство согласованности (в сети — запрос к логу).
        #[arg(long)] log: PathBuf,
        #[arg(long)] head: PathBuf,
        #[arg(short, long)] out: PathBuf,
    },
    /// Доказательство включения записи под головой.
    LogProve {
        #[arg(long)] log: PathBuf,
        #[arg(long)] index: u64,
        #[arg(long)] head: PathBuf,
        #[arg(long = "cosig")] cosigs: Vec<PathBuf>,
        #[arg(short, long)] out: PathBuf,
    },
    /// Собрать цепочку, которую хост показывает клиентам.
    Bundle {
        #[arg(long)] control: PathBuf,
        #[arg(long)] zone: PathBuf,
        #[arg(long)] zone_proof: PathBuf,
        #[arg(long)] registrar: Option<PathBuf>,
        #[arg(long)] registrar_proof: Option<PathBuf>,
        #[arg(long)] domain: PathBuf,
        #[arg(long)] domain_proof: PathBuf,
        #[arg(long)] dns: PathBuf,
        #[arg(short, long)] out: PathBuf,
    },
    /// Проверить цепочку так, как это делает клиент.
    Verify {
        #[arg(long)] root: PublicKey,
        /// Свидетели, которым верим (можно несколько).
        #[arg(long = "witness")] witnesses: Vec<PublicKey>,
        /// Сколько свидетелей должны подписать голову. 0 — не требовать (только отладка).
        #[arg(long, default_value_t = 1)] threshold: usize,
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

fn logged<T: serde::de::DeserializeOwned>(cert: &Path, proof: &Path) -> Result<Logged<T>> {
    Ok(Logged { cert: read(cert)?, proof: read::<Proof>(proof)? })
}

/// Изменяемое состояние (лог, свидетель): пишем во временный файл и переименовываем.
fn save(path: &Path, text: &str) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
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
        Cmd::LogAdd { log, kind, cert } => {
            let entry = match kind {
                EntryKind::Zone => entry_of(&read::<Signed<ZoneCert>>(&cert)?),
                EntryKind::Registrar => entry_of(&read::<Signed<RegistrarCert>>(&cert)?),
                EntryKind::Domain => entry_of(&read::<Signed<DomainRecord>>(&cert)?),
            };
            let mut l: Log = if log.exists() { read(&log)? } else { Log::default() };
            match l.entries.iter().position(|e| *e == entry) {
                Some(i) => println!("{i} (уже в логе)"),
                None => {
                    let i = l.append(entry);
                    save(&log, &to_json(&l))?;
                    println!("{i}");
                }
            }
        }
        Cmd::LogHead { log, key, out } => {
            let l: Log = read(&log)?;
            write_new(&out, &to_json(&l.head(&load_key(&key)?, now())))?
        }
        Cmd::Cosign { witness_key, state, log, head, out } => {
            let (key, h, l): (_, Signed<TreeHead>, Log) = (load_key(&witness_key)?, read(&head)?, read(&log)?);
            let mut w: Witness = if state.exists() { read(&state)? } else { Witness::default() };
            let seen = w.size_of(&h.body.log);
            let consistency = if 0 < seen && seen < h.body.size {
                l.consistency(seen, h.body.size).ok_or_else(|| anyhow!("в логе нет записей до размера {}", h.body.size))?
            } else {
                vec![]
            };
            let c = w.cosign(&key, &h, &consistency, now())?;
            save(&state, &to_json(&w))?;
            write_new(&out, &to_json(&c))?
        }
        Cmd::LogProve { log, index, head, cosigs, out } => {
            let (l, h): (Log, Signed<TreeHead>) = (read(&log)?, read(&head)?);
            let cosigs = cosigs.iter().map(|p| read::<Cosig>(p)).collect::<Result<Vec<_>>>()?;
            let p = l.prove(index, &h, cosigs).ok_or_else(|| anyhow!("лог не соответствует голове или индекс вне дерева"))?;
            write_new(&out, &to_json(&p))?
        }
        Cmd::Bundle { control, zone, zone_proof, registrar, registrar_proof, domain, domain_proof, dns, out } => {
            let registrar = match (registrar, registrar_proof) {
                (Some(c), Some(p)) => Some(logged(&c, &p)?),
                (None, None) => None,
                _ => bail!("--registrar и --registrar-proof нужны вместе"),
            };
            let b = Bundle {
                control: read(&control)?,
                zone: logged(&zone, &zone_proof)?,
                registrar,
                domain: logged(&domain, &domain_proof)?,
                dns: read(&dns)?,
            };
            write_new(&out, &to_json(&b))?
        }
        Cmd::Verify { root, witnesses, threshold, bundle, notices } => {
            if threshold > witnesses.len() {
                bail!("порог {threshold} больше числа свидетелей ({})", witnesses.len());
            }
            let notices = notices.iter().map(|p| read(p)).collect::<Result<Vec<_>>>()?;
            let r = verify(&Trust { root, witnesses, threshold }, &read(&bundle)?, &notices, now())?;
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
