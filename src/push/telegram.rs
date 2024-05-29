use crate::error::Result;
use async_trait::async_trait;
use teloxide::{prelude::*, types::ParseMode};

use super::{msg_template::escape_markdown, MessageBot};

#[derive(Debug, Clone)]
pub struct Telegram {
    pub bot: Bot,
    pub chat_id: ChatId,
}

#[async_trait]
impl MessageBot for Telegram {
    async fn push_markdown(&self, _title: String, msg: String) -> Result<()> {
        let msg = escape_markdown(msg);
        self.bot
            .send_message(self.chat_id, msg)
            .parse_mode(ParseMode::MarkdownV2)
            .send()
            .await?;
        Ok(())
    }
}

impl Telegram {
    pub fn new(token: String, chat_id: i64) -> Self {
        Telegram {
            bot: Bot::new(token),
            chat_id: ChatId(chat_id),
        }
    }
}
