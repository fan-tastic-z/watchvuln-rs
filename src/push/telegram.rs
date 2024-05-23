use crate::error::Result;
use teloxide::{prelude::*, types::ParseMode};

#[derive(Debug, Clone)]
pub struct Telegram {
    pub bot: Bot,
    pub chat_id: ChatId,
}

impl Telegram {
    pub fn new(token: String, chat_id: i64) -> Self {
        Telegram {
            bot: Bot::new(token),
            chat_id: ChatId(chat_id),
        }
    }

    pub async fn push_markdown(&self, msg: String) -> Result<()> {
        self.bot
            .send_message(self.chat_id, msg)
            .parse_mode(ParseMode::MarkdownV2)
            .send()
            .await?;
        Ok(())
    }
}
