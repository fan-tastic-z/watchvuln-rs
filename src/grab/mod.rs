pub mod avd;

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
}

#[derive(Debug, Clone)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}
