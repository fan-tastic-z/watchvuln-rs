use crate::{config::Config, error::Result};
use async_trait::async_trait;
use dingding::DingDing;
use std::sync::Arc;
use telegram::Telegram;

pub mod dingding;
pub mod msg_template;
pub mod telegram;

#[async_trait]
pub trait MessageBot: Send + Sync {
    async fn push_markdown(&self, title: String, msg: String) -> Result<()>;
}

#[derive(Clone, Default)]
pub struct BotManager {
    pub bots: Vec<Arc<Box<dyn MessageBot>>>,
}

impl BotManager {
    pub fn new() -> Self {
        BotManager { bots: Vec::new() }
    }

    pub fn add_bot<T: MessageBot + 'static>(&mut self, bot: T) {
        self.bots.push(Arc::new(Box::new(bot)));
    }
}

pub fn init(config: Config) -> BotManager {
    let mut bots = BotManager::new();
    if !config.tg_bot.token.trim().is_empty() {
        let tg_bot = Telegram::new(config.tg_bot.token, config.tg_bot.chat_id);
        bots.add_bot(tg_bot)
    }
    if !config.ding_bot.access_token.trim().is_empty() {
        let ding_bot = DingDing::new(config.ding_bot.access_token, config.ding_bot.secret_token);
        bots.add_bot(ding_bot);
    }
    bots
}
