// use std::str::FromStr;

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_variant::to_variant_name;

use crate::config::Config;
use crate::error::Result;

pub const DEFAULT_ENVIRONMENT: &str = "development";

pub fn resolve_from_env() -> String {
    std::env::var("APP_ENV")
        .or_else(|_| std::env::var("NODE_ENV"))
        .unwrap_or_else(|_| DEFAULT_ENVIRONMENT.to_string())
}

impl From<String> for Environment {
    fn from(env: String) -> Self {
        Self::from_str(&env).unwrap_or(Self::Any(env))
    }
}

/// Application environment
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum Environment {
    #[serde(rename = "production")]
    Production,
    #[serde(rename = "development")]
    Development,
    #[serde(rename = "test")]
    Test,
    Any(String),
}

impl Environment {
    pub fn load(&self) -> Result<Config> {
        Config::new(self)
    }
}

impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Any(s) => s.fmt(f),
            _ => to_variant_name(self).expect("only enum supported").fmt(f),
        }
    }
}

impl FromStr for Environment {
    type Err = &'static str;

    fn from_str(input: &str) -> std::result::Result<Self, Self::Err> {
        match input {
            "production" => Ok(Self::Production),
            "development" => Ok(Self::Development),
            "test" => Ok(Self::Test),
            s => Ok(Self::Any(s.to_string())),
        }
    }
}
