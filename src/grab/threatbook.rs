use async_trait::async_trait;
use reqwest::header;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    error::Result,
    grab::Severity,
    utils::{check_over_two_week, http_client::Help},
};

use super::{Grab, Provider, VulnInfo};

const HOME_PAGE_URL: &str = "https://x.threatbook.com/v5/node/vul_module/homePage";
const LINK: &str = "https://x.threatbook.com/v5/vulIntelligence";

#[derive(Default)]
pub struct ThreadBookCrawler {
    pub name: String,
    pub display_name: String,
    pub link: String,
    pub help: Help,
}

#[async_trait]
impl Grab for ThreadBookCrawler {
    async fn get_update(&self, _page_limit: i32) -> Result<Vec<VulnInfo>> {
        let crawler = ThreadBookCrawler::new();
        let home_page_resp: ThreadBookHomePage =
            crawler.help.get_json(HOME_PAGE_URL).await?.json().await?;
        info!(
            "thread book get {} vulns",
            home_page_resp.data.high_risk.len()
        );
        let mut res = Vec::with_capacity(home_page_resp.data.high_risk.len());
        for v in home_page_resp.data.high_risk {
            let mut is_valuable = false;
            if let Ok(res) = self.check_valuable(&v) {
                is_valuable = res
            }

            let disclosure = self.get_disclosure(&v);

            let mut tags = Vec::new();
            if let Some(is_0day) = v.is_0day {
                if is_0day {
                    tags.push("0day".to_string());
                }
            }
            if v.poc_exist {
                tags.push("有Poc".to_string());
            }
            if v.premium {
                tags.push("有漏洞分析".to_string());
            }
            if v.solution {
                tags.push("有修复方案".to_string());
            }
            let vuln = VulnInfo {
                unique_key: v.id,
                title: v.vuln_name_zh,
                description: "".to_string(),
                severity: Severity::Critical,
                cve: "".to_string(),
                disclosure,
                references: Vec::new(),
                solutions: "".to_string(),
                from: LINK.to_string(),
                tags,
                reasons: Vec::new(),
                is_valuable,
            };
            res.push(vuln);
        }
        Ok(res)
    }

    fn get_provider(&self) -> Provider {
        Provider {
            name: self.name.to_owned(),
            display_name: self.display_name.to_owned(),
            link: self.link.to_owned(),
        }
    }

    fn get_name(&self) -> String {
        self.name.to_owned()
    }
}

impl ThreadBookCrawler {
    pub fn new() -> ThreadBookCrawler {
        let mut headers: reqwest::header::HeaderMap = header::HeaderMap::new();
        headers.insert("Referer", header::HeaderValue::from_static(LINK));
        headers.insert(
            "Origin",
            header::HeaderValue::from_static("https://mp.weixin.qq.com/"),
        );
        headers.insert(
            "Accept-Language",
            header::HeaderValue::from_static("zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6"),
        );
        let help = Help::new(headers);
        ThreadBookCrawler {
            name: "threatbook".to_string(),
            display_name: "微步在线研究响应中心-漏洞通告".to_string(),
            link: LINK.to_string(),
            help,
        }
    }

    pub fn get_disclosure(&self, data: &HighRisk) -> String {
        if !data.vuln_publish_time.is_empty() {
            data.vuln_publish_time.clone()
        } else if let Some(vuln_update_time) = &data.vuln_update_time {
            if !vuln_update_time.is_empty() {
                vuln_update_time.to_string()
            } else {
                "".to_string()
            }
        } else {
            "".to_string()
        }
    }

    pub fn check_valuable(&self, data: &HighRisk) -> Result<bool> {
        if !data.poc_exist || !data.premium {
            return Ok(false);
        }

        if data.vuln_publish_time.is_empty() && data.vuln_update_time.is_none() {
            return Ok(false);
        }
        if !data.vuln_publish_time.is_empty() {
            return check_over_two_week(&data.vuln_publish_time);
        }
        if let Some(vuln_update_time) = &data.vuln_update_time {
            if !vuln_update_time.is_empty() {
                return check_over_two_week(vuln_update_time);
            }
        }

        Ok(false)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadBookHomePage {
    pub data: Data,
    pub response_code: i32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Data {
    #[serde(rename = "highrisk")]
    pub high_risk: Vec<HighRisk>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighRisk {
    pub id: String,
    pub vuln_name_zh: String,
    pub vuln_update_time: Option<String>,
    pub affects: Vec<String>,
    pub vuln_publish_time: String,
    #[serde(rename = "pocExist")]
    pub poc_exist: bool,
    pub solution: bool,
    pub premium: bool,
    #[serde(rename = "riskLevel")]
    pub risk_level: String,
    #[serde(rename = "is0day")]
    pub is_0day: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_threat_book_homepage() -> Result<()> {
        let crawler = ThreadBookCrawler::new();
        let res: ThreadBookHomePage = crawler.help.get_json(HOME_PAGE_URL).await?.json().await?;
        info!("{:?}", res);
        Ok(())
    }
}
