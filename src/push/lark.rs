use async_trait::async_trait;
use base64::prelude::*;
use hmac::{Hmac, Mac};
use reqwest::header;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use snafu::{ensure, ResultExt};

use crate::error::{CryptoSnafu, HttpClientErrSnafu, LarkPushErrSnafu, Result};
use crate::utils::http_client::Help;

use super::MessageBot;

const LARK_HOOK_URL: &str = "https://open.feishu.cn/open-apis/bot/v2/hook";
const MSG_TYPE: &str = "interactive";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lark {
    pub access_token: String,
    pub secret_token: String,
}

#[async_trait]
impl MessageBot for Lark {
    async fn push_markdown(&self, title: String, msg: String) -> Result<()> {
        let help = self.get_help();
        let message = self.generate_lark_card(title, msg)?;
        let url = format!("{}/{}", LARK_HOOK_URL, self.access_token);
        let url_clone = url.clone();
        let send_res = help
            .http_client
            .post(&url)
            .json(&message)
            .send()
            .await
            .with_context(|_| HttpClientErrSnafu { url: url_clone })?;
        let res: LarkResponse = send_res
            .json()
            .await
            .with_context(|_| HttpClientErrSnafu { url })?;
        ensure!(res.code != 0, LarkPushErrSnafu { code: res.code });

        Ok(())
    }
}

impl Lark {
    pub fn new(access_token: String, secret_token: String) -> Self {
        Lark {
            access_token,
            secret_token,
        }
    }

    pub fn get_help(&self) -> Help {
        let mut headers = header::HeaderMap::new();
        headers.insert("Accept-Charset", header::HeaderValue::from_static("utf8"));
        Help::new(headers)
    }

    pub fn generate_sign(&self, timestamp: i64) -> Result<String> {
        let timestamp_and_secret = format!("{}\n{}", timestamp, self.secret_token);
        let hmac: Hmac<Sha256> =
            Hmac::new_from_slice(timestamp_and_secret.as_bytes()).context(CryptoSnafu)?;
        let hmac_code = hmac.finalize().into_bytes();
        let sign = BASE64_STANDARD.encode(hmac_code);
        Ok(sign)
    }

    pub fn generate_lark_card(&self, title: String, message: String) -> Result<serde_json::Value> {
        println!("{}", title);
        println!("{}", message);
        let message = message.replace("&nbsp", "");
        let now = chrono::Local::now().timestamp();
        let sign = self.generate_sign(now)?;
        let card = json!({
            "msg_type": MSG_TYPE,
            "card": {
                "elements": [
                    {
                        "tag": "div",
                        "text": {
                            "content": message,
                            "tag": "lark_md"
                        }

                    },
                ],
                "header": {
                    "title": {
                        "content": title,
                        "tag": "plain_text"
                    }
                }
            },
            "timestamp":now,
            "sign": sign,
        });
        Ok(card)
    }
}

// LarkResponse ignore data
#[derive(Debug, Serialize, Deserialize)]
pub struct LarkResponse {
    pub msg: String,
    pub code: i32,
}
