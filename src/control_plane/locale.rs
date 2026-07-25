use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Locale {
    En,
    Id,
    Ja,
}

impl Locale {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Id => "id",
            Self::Ja => "ja",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocaleError;

impl fmt::Display for LocaleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid locale")
    }
}

impl std::error::Error for LocaleError {}

pub fn validate_locale(value: &str) -> Result<Locale, LocaleError> {
    match value {
        "en" => Ok(Locale::En),
        "id" => Ok(Locale::Id),
        "ja" => Ok(Locale::Ja),
        _ => Err(LocaleError),
    }
}
