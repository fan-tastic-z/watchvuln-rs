use std::{num::ParseIntError, time::SystemTimeError};

use hmac::digest::crypto_common;
use migration::sea_orm;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{inner}\n{backtrace}")]
    WithBacktrace {
        inner: Box<Self>,
        backtrace: Box<std::backtrace::Backtrace>,
    },

    // Model
    #[error(transparent)]
    Model(#[from] crate::models::ModelError),

    #[error("{0}")]
    Message(String),

    #[error(transparent)]
    HmacError(#[from] crypto_common::InvalidLength),

    #[error(transparent)]
    CronScheduler(#[from] tokio_cron_scheduler::JobSchedulerError),

    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    #[error(transparent)]
    Regex(#[from] regex::Error),

    #[error(transparent)]
    ParseInt(#[from] ParseIntError),

    #[error(transparent)]
    ParseUrl(#[from] url::ParseError),

    #[error(transparent)]
    DB(#[from] sea_orm::DbErr),

    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),

    #[error(transparent)]
    Tera(#[from] tera::Error),

    #[error(transparent)]
    JSON(serde_json::Error),

    #[error("cannot parse `{1}`: {0}")]
    YAMLFile(#[source] serde_yaml::Error, String),

    #[error(transparent)]
    YAML(#[from] serde_yaml::Error),

    #[error(transparent)]
    TELOXIDE(#[from] teloxide::RequestError),

    #[error(transparent)]
    EnvVar(#[from] std::env::VarError),

    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error(transparent)]
    DateParse(#[from] chrono::ParseError),

    #[error(transparent)]
    SystemTime(#[from] SystemTimeError),

    #[error(transparent)]
    Octocrab(#[from] octocrab::Error),

    #[error(transparent)]
    Any(#[from] Box<dyn std::error::Error + Send + Sync>),

    #[error(transparent)]
    Anyhow(#[from] eyre::Report),
}

impl Error {
    pub fn wrap(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Any(Box::new(err))
    }

    pub fn msg(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Message(err.to_string())
    }

    pub fn string(s: &str) -> Self {
        Self::Message(s.to_string())
    }

    pub fn bt(self) -> Self {
        let backtrace = std::backtrace::Backtrace::capture();
        match backtrace.status() {
            std::backtrace::BacktraceStatus::Disabled
            | std::backtrace::BacktraceStatus::Unsupported => self,
            _ => Self::WithBacktrace {
                inner: Box::new(self),
                backtrace: Box::new(backtrace),
            },
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(val: serde_json::Error) -> Self {
        Self::JSON(val).bt()
    }
}
