//! Настройки браузера. Хранятся в `<каталог данных>/settings.json`; применяются на лету во всех окнах.
//! Значения проверяются при записи: страница настроек — это код приложения, но файл на диске могли править руками.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Допустимые акценты (те же id, что в `ui/kit.js`).
pub const ACCENTS: [&str; 6] = ["blue", "teal", "amber", "red", "violet", "white"];
const BLURS: [&str; 3] = ["off", "soft", "strong"];
const MOTIONS: [&str; 4] = ["system", "full", "reduced", "off"];
pub const DIM_MAX: u8 = 80;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Акцентный цвет интерфейса.
    pub accent: String,
    /// Размытие фона за меню и окнами: `off`, `soft`, `strong` (только где его умеет система).
    pub blur: String,
    /// Затемнение за модальными окнами, 0..=80 %.
    pub dim: u8,
    /// Анимации: `system` (как в системе), `full`, `reduced`, `off`.
    pub motion: String,
    /// Адрес без схемы сначала ищется в Rift (P7), а не в интернете.
    pub rift_first: bool,
    /// Записывать историю посещений.
    pub save_history: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self { accent: "blue".into(), blur: "soft".into(), dim: 45, motion: "system".into(), rift_first: true, save_history: true }
    }
}

impl Settings {
    /// Применяет частичное изменение `{"ключ": значение}`. При любой ошибке ничего не меняется.
    pub fn patch(&mut self, patch: &Value) -> Result<(), String> {
        let obj: &Map<String, Value> = patch.as_object().ok_or("ожидался объект с настройками")?;
        let mut next = self.clone();
        for (k, v) in obj {
            let pick = |allowed: &[&str]| -> Result<String, String> {
                let s = v.as_str().ok_or_else(|| format!("«{k}»: ожидалась строка"))?;
                allowed.contains(&s).then(|| s.to_string()).ok_or_else(|| format!("«{k}»: недопустимое значение «{s}»"))
            };
            match k.as_str() {
                "accent" => next.accent = pick(&ACCENTS)?,
                "blur" => next.blur = pick(&BLURS)?,
                "motion" => next.motion = pick(&MOTIONS)?,
                "dim" => {
                    let n = v.as_f64().filter(|n| n.is_finite()).ok_or("«dim»: ожидалось число")?;
                    next.dim = n.round().clamp(0.0, f64::from(DIM_MAX)) as u8;
                }
                "rift_first" => next.rift_first = v.as_bool().ok_or("«rift_first»: ожидалось true или false")?,
                "save_history" => next.save_history = v.as_bool().ok_or("«save_history»: ожидалось true или false")?,
                other => return Err(format!("неизвестная настройка «{other}»")),
            }
        }
        *self = next;
        Ok(())
    }

    /// Читает файл. Нет файла — значения по умолчанию; испорченный файл — ошибка (молча затирать настройки нельзя).
    /// Значения из файла проходят ту же проверку, что и запись из страницы.
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e).with_context(|| format!("не удалось прочитать {}", path.display())),
        };
        let v: Value = serde_json::from_slice(&bytes).with_context(|| format!("{}: повреждён", path.display()))?;
        let mut s = Self::default();
        s.patch(&v).map_err(anyhow::Error::msg).with_context(|| format!("{}: недопустимые настройки", path.display()))?;
        Ok(s)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, path).with_context(|| format!("не удалось записать {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn patch_applies_valid_values_and_clamps_dim() {
        let mut s = Settings::default();
        s.patch(&json!({"accent": "amber", "blur": "strong", "motion": "off", "dim": 33.4, "rift_first": false, "save_history": false})).unwrap();
        assert!(!s.save_history);
        assert_eq!((s.accent.as_str(), s.blur.as_str(), s.motion.as_str(), s.dim, s.rift_first), ("amber", "strong", "off", 33, false));
        s.patch(&json!({"dim": 500})).unwrap();
        assert_eq!(s.dim, DIM_MAX);
        s.patch(&json!({"dim": -5})).unwrap();
        assert_eq!(s.dim, 0);
    }

    #[test]
    fn patch_is_all_or_nothing_and_rejects_garbage() {
        let mut s = Settings::default();
        let before = s.clone();
        for bad in [
            json!({"accent": "neon"}), json!({"accent": 5}), json!({"blur": "huge"}), json!({"motion": ""}), json!({"dim": "много"}),
            json!({"dim": null}), json!({"rift_first": "да"}), json!({"save_history": 1}), json!({"unknown": 1}), json!([1]), json!("x"),
            json!({"accent": "red", "blur": "huge"}), // первое допустимо, второе нет: не применяется ничего
        ] {
            assert!(s.patch(&bad).is_err(), "{bad}");
            assert_eq!(s, before, "после отказа {bad} настройки изменились");
        }
    }

    #[test]
    fn file_roundtrip_missing_and_corrupt() {
        let dir = std::env::temp_dir().join(format!("rift-settings-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let path = dir.join("nested/settings.json");
        assert_eq!(Settings::load(&path).unwrap(), Settings::default(), "нет файла — по умолчанию");
        let mut s = Settings::default();
        s.patch(&json!({"accent": "teal", "dim": 20})).unwrap();
        s.save(&path).unwrap();
        assert_eq!(Settings::load(&path).unwrap(), s);
        // Руками вписали недопустимое — не принимаем и не затираем молча.
        std::fs::write(&path, r#"{"accent":"neon"}"#).unwrap();
        assert!(Settings::load(&path).is_err());
        std::fs::write(&path, "не json").unwrap();
        assert!(Settings::load(&path).is_err());
        std::fs::remove_dir_all(dir).ok();
    }
}
