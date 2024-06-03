use crate::{
    error::{Error, Result},
    utils::data_str_format,
};
use async_trait::async_trait;
use regex::Regex;
use reqwest::header;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, warn};

use crate::utils::http_client::Help;

use super::{Grab, VulnInfo};

const ANTI_LIST_URL: &str = "https://www.antiycloud.com/api/safeNotice/list";
const ANTI_CVEID_REGEXP: &str = r"CVE-\d+\-\d+";

#[derive(Default)]
pub struct AntiCrawler {
    pub name: String,
    pub display_name: String,
    pub link: String,
    pub help: Help,
}

#[async_trait]
impl Grab for AntiCrawler {
    async fn get_update(&self, _page_limit: i32) -> Result<Vec<VulnInfo>> {
        let anti_list_response = self.get_anti_list_response().await?;
        // anti is the data summarized on a daily basis. Only the latest day’s data is obtained here.
        let first_data = &anti_list_response.data.list[0].body;
        let mut res = Vec::with_capacity(first_data.len());
        let disclosure_time = &anti_list_response.data.list[0].notice_time;
        let disclosure = data_str_format(disclosure_time)?;
        for data in first_data.iter() {
            let description = self.get_description(data);
            let title = data.title.clone().split_off(2);
            let cve = self.get_cve(&title);

            let unique_key = match cve {
                Ok(unique_key) => unique_key,
                Err(e) => {
                    warn!("AntiCrawler get update not found cve error:{}", e);
                    continue;
                }
            };
            let solutions = self.nth(data, 3);
            let from = format!(
                "https://www.antiycloud.com/#/infodetail/{}",
                disclosure_time
            );
            let references = self.get_references(data);
            let vuln = VulnInfo {
                unique_key: unique_key.clone(),
                title,
                description,
                severity: super::Severity::High,
                cve: unique_key,
                disclosure: disclosure.clone(),
                references,
                solutions,
                from,
                tags: vec![],
                reasons: vec![],
                is_valuable: true,
            };
            res.push(vuln);
        }
        info!("{} crawling count {}", self.get_name(), res.len());
        Ok(res)
    }

    fn get_name(&self) -> String {
        self.display_name.to_owned()
    }
}

impl AntiCrawler {
    pub fn new() -> Self {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            "Origin",
            header::HeaderValue::from_static("https://www.antiycloud.com"),
        );
        headers.insert(
            "Referer",
            header::HeaderValue::from_static("https://www.antiycloud.com"),
        );
        let help = Help::new(headers);
        AntiCrawler {
            name: "antiycloud".to_string(),
            display_name: "安天威胁情报中心".to_string(),
            link: "https://www.antiycloud.com/#/antiy/safenotice".to_string(),
            help,
        }
    }

    async fn get_anti_list_response(&self) -> Result<AntiResponse> {
        let params = json!({
            "search":{
                "value":""
            },
            "type":"",
            "pagination":{
                "current":1,
                "pageSize":10,
                "total":0
            },
            "sorter":{
                "field":"ar_time",
                "order":"descend"
            },
            "dict":{
                "time_range":[]
            }
        });
        let anti_response: AntiResponse = self
            .help
            .post_json(ANTI_LIST_URL, &params)
            .await?
            .json()
            .await?;
        Ok(anti_response)
    }

    fn nth(&self, data: &Body, n: usize) -> String {
        if n == 0 {
            data.body[n].content[1].data.clone()
        } else {
            let mut res = "".to_string();
            for c in &data.body[n].content {
                res += &c.data;
            }
            res
        }
    }

    fn get_references(&self, data: &Body) -> Vec<String> {
        let mut references = Vec::new();
        for c in &data.body[3].content {
            if c.r#type == "link" {
                references.push(c.data.clone());
            }
        }
        references
    }

    fn get_description(&self, data: &Body) -> String {
        let description = self.nth(data, 0);
        let influence = self.get_sphere_of_influence(data);
        let description = format!("{}\n{}", description, influence);
        description
    }

    fn get_sphere_of_influence(&self, data: &Body) -> String {
        let influence = self.nth(data, 2);
        let res = format!("影响范围: \n {}", influence);
        res
    }

    fn get_cve(&self, title: &str) -> Result<String> {
        let res = Regex::new(ANTI_CVEID_REGEXP)?.captures(title);
        if let Some(cve) = res {
            Ok(cve[0].to_string())
        } else {
            Err(Error::Message("cve regex match not found".to_owned()))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiResponse {
    pub status: String,
    pub data: Data,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Data {
    pub current: i32,
    pub total: i32,
    pub list: Vec<List>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct List {
    pub id: i32,
    pub title: String,
    #[serde(rename = "typeId")]
    pub type_id: i32,
    pub m_type: String,
    pub visitcount: i32,
    pub r#abstract: String,
    pub content: String,
    pub department: String,
    pub r#type: String,
    pub time: String,
    pub notice_time: String,
    pub body: Vec<Body>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Body {
    pub title: String,
    pub body: Vec<BodyDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BodyDetail {
    pub subtitle: String,
    pub content: Vec<ContentDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentDetail {
    pub data: String,
    pub r#type: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_anti_response() -> Result<()> {
        let anti = AntiCrawler::new();
        let res = anti.get_anti_list_response().await?;
        println!("{:?}", res);
        Ok(())
    }

    #[tokio::test]
    async fn test_get_update() -> Result<()> {
        let anti = AntiCrawler::new();
        let res = anti.get_update(1).await?;
        println!("{:?}", res);
        Ok(())
    }

    #[test]
    fn test_get_cve() -> Result<()> {
        let anti = AntiCrawler::new();
        let res = anti.get_cve("1 Check Point安全网关 MyCRL 任意文件读取漏洞(CVE-2024-24919)")?;
        assert_eq!(res, "CVE-2024-24919");
        Ok(())
    }
}
