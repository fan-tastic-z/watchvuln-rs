use std::collections::HashMap;

use crate::grab::{oscs::OscCrawler, AVDCrawler, Grab};

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
    manager
}
