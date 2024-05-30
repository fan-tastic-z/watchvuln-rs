use std::time::SystemTime;

use crate::{
    error::{Error, Result},
    utils::{calc_hmac_sha256, http_client::Help},
};
use async_trait::async_trait;
use base64::prelude::*;
use reqwest::header;
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::MessageBot;

const DING_API_URL: &str = "https://oapi.dingtalk.com/robot/send";
const MSG_TYPE: &str = "markdown";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DingDing {
    pub access_token: String,
    pub secret_token: String,
}

#[async_trait]
impl MessageBot for DingDing {
    async fn push_markdown(&self, title: String, msg: String) -> Result<()> {
        let help = self.get_help();

        let msg = msg.replace("\n\n", "\n\n&nbsp;\n");
        let message = serde_json::json!({
            "msgtype": MSG_TYPE,
            "markdown": {
                "title": title,
                "text": msg
            },
        });

        let sign = self.generate_sign()?;

        let res: DingResponse = help
            .http_client
            .post(DING_API_URL)
            .query(&sign)
            .json(&message)
            .send()
            .await?
            .json()
            .await?;

        if res.errcode != 0 {
            warn!(
                "ding push markdown message error, err msg is {}",
                res.errmsg
            );
            return Err(Error::Message(
                "ding push markdown message response errorcode not eq 0".to_owned(),
            ));
        }
        Ok(())
    }
}

impl DingDing {
    pub fn new(access_token: String, secret_token: String) -> Self {
        DingDing {
            access_token,
            secret_token,
        }
    }

    pub fn get_help(&self) -> Help {
        let mut headers = header::HeaderMap::new();
        headers.insert("Accept-Charset", header::HeaderValue::from_static("utf8"));
        Help::new(headers)
    }
    pub fn generate_sign(&self) -> Result<Sign> {
        let sign = if !self.secret_token.is_empty() {
            let timestamp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis();
            let timestamp_and_secret = &format!("{}\n{}", timestamp, self.secret_token);
            let hmac_sha256 = calc_hmac_sha256(
                self.secret_token.as_bytes(),
                timestamp_and_secret.as_bytes(),
            )?;
            let sign = BASE64_STANDARD.encode(hmac_sha256);
            Sign {
                access_token: self.access_token.clone(),
                timestamp: Some(timestamp),
                sign: Some(sign),
            }
        } else {
            Sign {
                access_token: self.access_token.clone(),
                timestamp: None,
                sign: None,
            }
        };
        Ok(sign)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sign {
    pub access_token: String,
    pub timestamp: Option<u128>,
    pub sign: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DingResponse {
    pub errmsg: String,
    pub errcode: i64,
}
