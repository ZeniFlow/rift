//! История и закладки: два JSON-файла в каталоге данных (`history.json`, `bookmarks.json`).
//! Адреса хранятся так, как их видит пользователь (`rift://имя.зона/путь`, `https://…`), а не адреса шлюза.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Сколько посещений помним. Старые вытесняются.
pub const HISTORY_MAX: usize = 5000;
/// Повторное открытие того же адреса в течение этого времени — одна запись (перезагрузка, редиректы).
const MERGE_MS: u64 = 30_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub url: String,
    pub title: String,
    /// Unix-время, мс.
    pub ts: u64,
}

#[derive(Debug, Default)]
pub struct Store {
    dir: Option<PathBuf>,
    history: Vec<Entry>, // от старых к новым
    marks: Vec<Entry>,   // от старых к новым
}

fn read(path: &Path) -> Result<Vec<Entry>> {
    match std::fs::read(path) {
        Ok(b) => serde_json::from_slice(&b).with_context(|| format!("{}: повреждён", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(e).with_context(|| format!("не удалось прочитать {}", path.display())),
    }
}

fn write(path: &Path, v: &[Entry]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec(v)?)?;
    std::fs::rename(&tmp, path).with_context(|| format!("не удалось записать {}", path.display()))
}

impl Store {
    /// `None` — только в памяти (самопроверки). Повреждённый файл откладывается в `*.bad`, а не затирается молча.
    pub fn load(dir: Option<&Path>) -> Self {
        let Some(dir) = dir else { return Self::default() };
        let get = |name: &str| {
            let p = dir.join(name);
            read(&p).unwrap_or_else(|e| {
                eprintln!("{e:#}: откладываю в {name}.bad, начинаю с пустого");
                std::fs::rename(&p, dir.join(format!("{name}.bad"))).ok();
                vec![]
            })
        };
        Self { dir: Some(dir.to_path_buf()), history: get("history.json"), marks: get("bookmarks.json") }
    }

    // ponytail: файл целиком при каждом изменении (5000 записей ≈ 0.5 МБ); дописывать журналом, если станет заметно.
    fn save(&self) {
        let Some(d) = &self.dir else { return };
        let r = std::fs::create_dir_all(d).map_err(Into::into).and_then(|()| write(&d.join("history.json"), &self.history)).and_then(|()| write(&d.join("bookmarks.json"), &self.marks));
        if let Err(e) = r {
            eprintln!("не удалось сохранить историю или закладки: {e:#}");
        }
    }

    /// Записывает посещение. Тот же адрес подряд в пределах 30 с обновляет последнюю запись.
    pub fn visit(&mut self, url: &str, title: &str, now: u64) {
        match self.history.last_mut() {
            Some(l) if l.url == url && now.saturating_sub(l.ts) < MERGE_MS => {
                l.ts = now;
                if !title.is_empty() {
                    l.title = title.into();
                }
            }
            _ => {
                self.history.push(Entry { url: url.into(), title: title.into(), ts: now });
                if self.history.len() > HISTORY_MAX {
                    self.history.drain(..self.history.len() - HISTORY_MAX);
                }
            }
        }
        self.save();
    }

    /// Новые сверху. Запрос ищется в адресе и заголовке без учёта регистра.
    pub fn history(&self, query: &str, limit: usize) -> Vec<Entry> {
        let q = query.trim().to_lowercase();
        self.history.iter().rev().filter(|e| q.is_empty() || e.url.to_lowercase().contains(&q) || e.title.to_lowercase().contains(&q)).take(limit).cloned().collect()
    }

    /// Удаляет все записи с этими адресами.
    pub fn forget(&mut self, urls: &[String]) {
        self.history.retain(|e| !urls.contains(&e.url));
        self.save();
    }

    pub fn clear_history(&mut self) {
        self.history.clear();
        self.save();
    }

    /// Самые частые адреса: (адрес, последний заголовок, число посещений).
    pub fn top(&self, n: usize) -> Vec<(String, String, usize)> {
        let mut by: Vec<(String, String, usize, u64)> = vec![];
        for e in &self.history {
            match by.iter_mut().find(|(u, ..)| *u == e.url) {
                Some(b) => (b.1, b.2, b.3) = (if e.title.is_empty() { b.1.clone() } else { e.title.clone() }, b.2 + 1, e.ts),
                None => by.push((e.url.clone(), e.title.clone(), 1, e.ts)),
            }
        }
        by.sort_by(|a, b| b.2.cmp(&a.2).then(b.3.cmp(&a.3)));
        by.into_iter().take(n).map(|(u, t, c, _)| (u, t, c)).collect()
    }

    /// Подсказки к набранному: закладки (новые сверху), затем адреса из истории: сначала те, что начинаются с запроса, потом чаще
    /// и свежее открывавшиеся. Каждый адрес один раз. Тип: `bookmark` или `history`.
    pub fn suggest(&self, query: &str, n: usize) -> Vec<(Entry, &'static str)> {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return vec![];
        }
        let hit = |e: &Entry| e.url.to_lowercase().contains(&q) || e.title.to_lowercase().contains(&q);
        let mut out: Vec<(Entry, &'static str)> = self.marks.iter().rev().filter(|e| hit(e)).map(|e| (e.clone(), "bookmark")).collect();
        let bare = |u: &str| u.split_once("://").map_or(u, |x| x.1).trim_start_matches("www.").to_lowercase();
        let mut seen: Vec<(String, String, usize, u64)> = vec![]; // адрес, заголовок, посещений, последнее
        for e in self.history.iter().filter(|e| hit(e)) {
            match seen.iter_mut().find(|s| s.0 == e.url) {
                Some(s) => (s.1, s.2, s.3) = (if e.title.is_empty() { s.1.clone() } else { e.title.clone() }, s.2 + 1, e.ts),
                None => seen.push((e.url.clone(), e.title.clone(), 1, e.ts)),
            }
        }
        seen.sort_by(|a, b| bare(&b.0).starts_with(&q).cmp(&bare(&a.0).starts_with(&q)).then(b.2.cmp(&a.2)).then(b.3.cmp(&a.3)));
        for (url, title, _, ts) in seen {
            if !out.iter().any(|(e, _)| e.url == url) {
                out.push((Entry { url, title, ts }, "history"));
            }
        }
        out.truncate(n);
        out
    }

    pub fn is_marked(&self, url: &str) -> bool {
        self.marks.iter().any(|m| m.url == url)
    }

    /// Ставит или снимает закладку. Возвращает, стоит ли она теперь.
    pub fn toggle_mark(&mut self, url: &str, title: &str, now: u64) -> bool {
        let on = !self.is_marked(url);
        if on {
            self.marks.push(Entry { url: url.into(), title: title.into(), ts: now });
        } else {
            self.marks.retain(|m| m.url != url);
        }
        self.save();
        on
    }

    pub fn remove_mark(&mut self, url: &str) {
        self.marks.retain(|m| m.url != url);
        self.save();
    }

    /// Новые сверху.
    pub fn marks(&self) -> Vec<Entry> {
        self.marks.iter().rev().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        std::env::temp_dir().join(format!("rift-store-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()))
    }

    #[test]
    fn visits_merge_only_same_url_within_window() {
        let mut s = Store::default();
        s.visit("rift://a.b/", "", 1000);
        s.visit("rift://a.b/", "A", 2000); // перезагрузка: одна запись, заголовок подтянулся
        assert_eq!(s.history("", 10), vec![Entry { url: "rift://a.b/".into(), title: "A".into(), ts: 2000 }]);
        s.visit("rift://a.b/", "A", 2000 + MERGE_MS); // позже окна: новая запись
        s.visit("rift://c.d/", "C", 40_000);
        s.visit("rift://a.b/", "A", 41_000); // не подряд: новая запись
        assert_eq!(s.history("", 10).len(), 4);
        assert_eq!(s.history("", 10)[0].url, "rift://a.b/", "новые сверху");
    }

    #[test]
    fn search_forget_clear_and_cap() {
        let mut s = Store::default();
        s.visit("https://example.com/x", "Пример", 1);
        s.visit("rift://shop.brand/", "Магазин", 100_000);
        assert_eq!(s.history("МАГАЗ", 10).len(), 1, "по заголовку, без учёта регистра");
        assert_eq!(s.history("example", 10).len(), 1, "по адресу");
        assert_eq!(s.history("", 1).len(), 1, "лимит");
        s.forget(&["https://example.com/x".into()]);
        assert_eq!(s.history("", 10).len(), 1);
        s.clear_history();
        assert!(s.history("", 10).is_empty());
        for i in 0..HISTORY_MAX + 10 {
            s.visit(&format!("https://e.com/{i}"), "", i as u64 * MERGE_MS);
        }
        let h = s.history("", usize::MAX);
        assert_eq!((h.len(), h[0].url.as_str()), (HISTORY_MAX, format!("https://e.com/{}", HISTORY_MAX + 9).as_str()));
        assert_eq!(h.last().unwrap().url, "https://e.com/10", "вытеснены самые старые");
    }

    #[test]
    fn top_sites_by_visits_then_recency() {
        let mut s = Store::default();
        for (u, t) in [("a", 0), ("b", 100_000), ("a", 200_000), ("c", 300_000), ("b", 400_000), ("a", 500_000)] {
            s.visit(u, "", t);
        }
        let top: Vec<_> = s.top(2).into_iter().map(|(u, _, c)| (u, c)).collect();
        assert_eq!(top, vec![("a".to_string(), 3), ("b".to_string(), 2)]);
    }

    #[test]
    fn suggestions_rank_bookmarks_then_prefix_then_popularity() {
        let mut s = Store::default();
        for (u, t, ms) in [("https://news.example/a", "Новости", 0), ("rift://shop.brand/", "Магазин", 100_000), ("https://example.com/", "Пример", 200_000), ("https://example.com/", "Пример", 300_000), ("https://my.site/example", "", 400_000)] {
            s.visit(u, t, ms);
        }
        s.toggle_mark("rift://shop.brand/", "Магазин", 1);
        assert!(s.suggest("", 5).is_empty() && s.suggest("  ", 5).is_empty(), "пустой запрос — без подсказок");
        let got: Vec<_> = s.suggest("exam", 5).into_iter().map(|(e, k)| (e.url, k)).collect();
        // «exam» есть в трёх адресах; example.com начинается с запроса; остальные не начинаются и открывались по разу — свежий выше.
        assert_eq!(got.iter().map(|g| g.0.as_str()).collect::<Vec<_>>(), ["https://example.com/", "https://my.site/example", "https://news.example/a"]);
        let got = s.suggest("магаз", 5);
        assert_eq!((got[0].0.url.as_str(), got[0].1), ("rift://shop.brand/", "bookmark"), "закладка по заголовку; в истории тот же адрес не дублируется");
        assert_eq!(got.len(), 1);
        assert_eq!(s.suggest("example", 2).len(), 2, "лимит");
    }

    #[test]
    fn bookmarks_toggle_and_persist() {
        let dir = tmp();
        let mut s = Store::load(Some(&dir));
        assert!(s.toggle_mark("rift://a.b/", "A", 1));
        assert!(s.is_marked("rift://a.b/"));
        s.toggle_mark("rift://c.d/", "C", 2);
        s.visit("rift://a.b/", "A", 3);
        let again = Store::load(Some(&dir));
        assert_eq!(again.marks().iter().map(|m| m.url.as_str()).collect::<Vec<_>>(), ["rift://c.d/", "rift://a.b/"], "новые сверху, пережили перезапуск");
        assert_eq!(again.history("", 5).len(), 1);
        assert!(!s.toggle_mark("rift://a.b/", "A", 4), "второй раз — снять");
        s.remove_mark("rift://c.d/");
        assert!(s.marks().is_empty());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn corrupt_file_is_set_aside_not_overwritten() {
        let dir = tmp();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("history.json"), "не json").unwrap();
        let mut s = Store::load(Some(&dir));
        assert!(s.history("", 5).is_empty());
        assert_eq!(std::fs::read_to_string(dir.join("history.json.bad")).unwrap(), "не json");
        s.visit("x", "", 1);
        assert_eq!(Store::load(Some(&dir)).history("", 5).len(), 1);
        std::fs::remove_dir_all(dir).ok();
    }
}
