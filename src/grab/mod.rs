pub mod avd;
pub mod oscs;

use std::fmt;

use crate::Result;
use async_trait::async_trait;
pub use avd::AVDCrawler;

#[derive(Debug, Clone)]
pub struct VulnInfo {
    pub unique_key: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub cve: String,
    pub disclosure: String,
    pub references: Vec<String>,
    pub solutions: String,
    pub from: String,
    pub tags: Vec<String>,
    pub reason: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug)]
pub struct Provider {
    pub name: String,
    pub display_name: String,
    pub link: String,
}

#[async_trait]
pub trait Grab: Send + Sync {
    async fn get_update(&self, page_limit: i32) -> Result<Vec<VulnInfo>>;
    fn get_provider(&self) -> Provider;
    fn get_name(&self) -> String;
}
