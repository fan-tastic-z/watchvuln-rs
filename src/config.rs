use std::path::{Path, PathBuf};

use crate::{environment::Environment, logger, utils::render_string, Error, Result};
use fs_err as fs;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use serde_json::json;

lazy_static! {
    static ref DEFAULT_FOLDER: PathBuf = PathBuf::from("config");
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub database: Database,
    pub task: Task,
    pub logger: Logger,
    pub tg_bot: TgBot,
}

impl Config {
    pub fn new(env: &Environment) -> Result<Self> {
        let config = Self::from_folder(env, DEFAULT_FOLDER.as_path())?;
        Ok(config)
    }
    pub fn from_folder(env: &Environment, path: &Path) -> Result<Self> {
        let files = [
            path.join(format!("{env}.local.yaml")),
            path.join(format!("{env}.yaml")),
        ];
        let selected_path = files
            .iter()
            .find(|p| p.exists())
            .ok_or_else(|| Error::Message("no configuration file found".to_string()))?;

        let content = fs::read_to_string(selected_path)?;
        let rendered = render_string(&content, &json!({}))?;
        serde_yaml::from_str(&rendered)
            .map_err(|err| Error::YAMLFile(err, selected_path.to_string_lossy().to_string()))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Database {
    pub uri: String,

    /// Enable SQLx statement logging
    pub enable_logging: bool,

    /// Minimum number of connections for a pool
    pub min_connections: u32,

    /// Maximum number of connections for a pool
    pub max_connections: u32,

    /// Set the timeout duration when acquiring a connection
    pub connect_timeout: u64,

    /// Set the idle duration before closing a connection
    pub idle_timeout: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Task {
    pub cron_config: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Logger {
    pub enable: bool,

    /// Enable nice display of backtraces, in development this should be on.
    /// Turn it off in performance sensitive production deployments.
    #[serde(default)]
    pub pretty_backtrace: bool,

    /// Set the logger level.
    ///
    /// * options: `trace` | `debug` | `info` | `warn` | `error`
    pub level: logger::LogLevel,

    /// Set the logger format.
    ///
    /// * options: `compact` | `pretty` | `json`
    pub format: logger::Format,

    /// Override our custom tracing filter.
    ///
    /// Set this to your own filter if you want to see traces from internal
    /// libraries. See more [here](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#directives)
    pub override_filter: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct TgBot {
    pub chat_id: i64,
    pub token: String,
}
