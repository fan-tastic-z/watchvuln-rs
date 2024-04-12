use std::path::{Path, PathBuf};

use crate::{environment::Environment, Error, Result};
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
        let rendered = crate::tera::render_string(&content, &json!({}))?;
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
