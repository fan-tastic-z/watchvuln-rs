pub mod avd;
pub mod oscs;
pub mod seebug;

use std::{collections::HashMap, fmt};

use crate::{models::_entities::vuln_informations::Model, Result};
use async_trait::async_trait;
pub use avd::AVDCrawler;
use serde::{Deserialize, Serialize};

use self::{oscs::OscCrawler, seebug::SeeBugCrawler};

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
}

impl From<Model> for VulnInfo {
    fn from(v: Model) -> Self {
        let severtiy = match v.severtiy.as_str() {
            "低危" => Severity::Low,
            "中危" => Severity::Medium,
            "高危" => Severity::High,
            "严重" => Severity::Critical,
            _ => Severity::Low,
        };

        let references = match v.references {
            Some(references) => references,
            None => Vec::new(),
        };

        let tags = match v.tags {
            Some(tags) => tags,
            None => Vec::new(),
        };

        let reasons = match v.reasons {
            Some(reasons) => reasons,
            None => Vec::new(),
        };

        VulnInfo {
            unique_key: v.key,
            title: v.title,
            description: v.description,
            severity: severtiy,
            cve: v.cve,
            disclosure: v.disclosure,
            references,
            solutions: v.solutions,
            from: v.from,
            tags,
            reasons,
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
    manager
}
