pub mod avd;
pub mod oscs;
pub mod seebug;

use std::{collections::HashMap, fmt};

use crate::Result;
use async_trait::async_trait;
pub use avd::AVDCrawler;

use self::{oscs::OscCrawler, seebug::SeeBugCrawler};

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
