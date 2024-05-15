use crate::config;
use serde::{Deserialize, Serialize};
use serde_variant::to_variant_name;
use time::macros::{format_description, offset};
use tracing_subscriber::{fmt::time::OffsetTime, EnvFilter};

const MODULE_WHITELIST: &[&str] = &[
    "watchvuln-rs",
    "sea_orm_migration",
    "tower_http",
    "sqlx::query",
];

// Define an enumeration for log levels
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub enum LogLevel {
    /// The "off" level.
    #[serde(rename = "off")]
    Off,
    /// The "trace" level.
    #[serde(rename = "trace")]
    Trace,
    /// The "debug" level.
    #[serde(rename = "debug")]
    Debug,
    /// The "info" level.
    #[serde(rename = "info")]
    #[default]
    Info,
    /// The "warn" level.
    #[serde(rename = "warn")]
    Warn,
    /// The "error" level.
    #[serde(rename = "error")]
    Error,
}

// Define an enumeration for log formats
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub enum Format {
    #[serde(rename = "compact")]
    #[default]
    Compact,
    #[serde(rename = "pretty")]
    Pretty,
    #[serde(rename = "json")]
    Json,
}

// Implement Display trait for LogLevel to enable pretty printing
impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        to_variant_name(self).expect("only enum supported").fmt(f)
    }
}

pub fn init(config: &config::Logger) {
    if !config.enable {
        return;
    }

    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| {
            // user wanted a specific filter, don't care about our internal whitelist
            // or, if no override give them the default whitelisted filter (most common)
            config.override_filter.as_ref().map_or_else(
                || {
                    EnvFilter::try_new(
                        MODULE_WHITELIST
                            .iter()
                            .map(|m| format!("{}={}", m, config.level))
                            .chain(std::iter::once(format!(
                                "{}={}",
                                "watchvuln-rs", config.level
                            )))
                            .collect::<Vec<_>>()
                            .join(","),
                    )
                },
                EnvFilter::try_new,
            )
        })
        .expect("logger initialization failed");
    let time_fmt =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]");
    let timer = OffsetTime::new(offset!(+8), time_fmt);
    let builder = tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(filter)
        .with_timer(timer);

    match config.format {
        Format::Compact => builder.compact().init(),
        Format::Pretty => builder.pretty().init(),
        Format::Json => builder.json().init(),
    }
}
