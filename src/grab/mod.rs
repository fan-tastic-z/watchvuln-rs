pub mod anti;
pub mod avd;
pub mod kev;
pub mod oscs;
pub mod seebug;
pub mod threatbook;
pub mod ti;

use std::{collections::HashMap, fmt};

use crate::{error::Result, models::_entities::vuln_informations::Model};
use anti::AntiCrawler;
use async_trait::async_trait;
pub use avd::AVDCrawler;
use serde::{Deserialize, Serialize};
use threatbook::ThreadBookCrawler;

use self::{kev::KevCrawler, oscs::OscCrawler, seebug::SeeBugCrawler, ti::TiCrawler};

#[derive(Debug, Clone, Deserialize, Serialize)]
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
    pub reasons: Vec<String>,
    pub github_search: Vec<String>,
    pub is_valuable: bool,
    pub pushed: bool,
}

impl From<Model> for VulnInfo {
    fn from(v: Model) -> Self {
        let severity = match v.severtiy.as_str() {
            "Low" => Severity::Low,
            "Medium" => Severity::Medium,
            "High" => Severity::High,
            "Critical" => Severity::Critical,
            _ => Severity::Low,
        };

        let references = v.references.unwrap_or_default();

        let tags = v.tags.unwrap_or_default();

        let reasons = v.reasons.unwrap_or_default();

        let github_search = v.github_search.unwrap_or_default();

        VulnInfo {
            unique_key: v.key,
            title: v.title,
            description: v.description,
            severity,
            cve: v.cve,
            disclosure: v.disclosure,
            references,
            solutions: v.solutions,
            from: v.from,
            tags,
            reasons,
            github_search,
            is_valuable: v.is_valuable,
            pushed: v.pushed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
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

#[async_trait]
pub trait Grab: Send + Sync {
    async fn get_update(&self, page_limit: i32) -> Result<Vec<VulnInfo>>;
    fn get_name(&self) -> String;
}

#[derive(Default)]
pub struct GrabManager {
    pub map: HashMap<String, Box<dyn Grab>>,
}

impl GrabManager {
    pub fn new() -> Self {
        GrabManager {
            map: HashMap::new(),
        }
    }
    pub fn register(&mut self, grab: Box<dyn Grab>) {
        self.map.insert(grab.get_name(), grab);
    }
    pub fn get(&self, name: &str) -> Option<&dyn Grab> {
        self.map.get(name).map(|grab| grab.as_ref())
    }
}

pub fn init() -> GrabManager {
    let mut manager = GrabManager::new();
    manager.register(Box::new(OscCrawler::new()));
    manager.register(Box::new(AVDCrawler::new()));
    manager.register(Box::new(SeeBugCrawler::new()));
    manager.register(Box::new(KevCrawler::new()));
    manager.register(Box::new(TiCrawler::new()));
    manager.register(Box::new(ThreadBookCrawler::new()));
    manager.register(Box::new(AntiCrawler::new()));
    manager
}
