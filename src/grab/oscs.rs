use async_trait::async_trait;
use chrono::{DateTime, FixedOffset};
use reqwest::header::{self};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::{
    error::{Error, Result},
    grab::{Severity, VulnInfo},
    utils::{http_client::Help, timestamp_to_date},
};

use super::{Grab, Provider};

const OSCS_PAGE_SIZE: i32 = 10;
const OSCS_PAGE_DEFAULT: i32 = 1;
const OSCS_PER_PAGE_DEFAULT: i32 = 10;
const OSCS_LIST_URL: &str = "https://www.oscs1024.com/oscs/v1/intelligence/list";
const OSCS_DETAIL_URL: &str = "https://www.oscs1024.com/oscs/v1/vdb/info";

pub struct OscCrawler {
    pub name: String,
    pub display_name: String,
    pub link: String,
    pub help: Help,
}

#[async_trait]
impl Grab for OscCrawler {
    async fn get_update(&self, page_limit: i32) -> Result<Vec<VulnInfo>> {
        let mut page_count = self.get_page_count().await?;
        if page_count > page_limit {
            page_count = page_limit;
        }
        let mut res = Vec::new();
        if let Some(i) = (1..=page_count).next() {
            let data = self.parse_page(i).await?;
            res.extend(data)
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

impl Default for OscCrawler {
    fn default() -> Self {
        Self::new()
    }
}

impl OscCrawler {
    pub fn new() -> Self {
        let headers = header::HeaderMap::new();
        let help = Help::new(headers);
        OscCrawler {
            name: "oscs".to_string(),
            display_name: "OSCS开源安全情报预警".to_string(),
            link: "https://www.oscs1024.com/cm".to_string(),
            help,
        }
    }

    pub async fn get_list_resp(&self, page: i32, per_page: i32) -> Result<OscsListResp> {
        let params = serde_json::json!({
            "page": page,
            "per_page": per_page,
        });
        let oscs_list_resp: OscsListResp = self
            .help
            .post_json(OSCS_LIST_URL, &params)
            .await?
            .json()
            .await?;
        Ok(oscs_list_resp)
    }

    pub async fn get_page_count(&self) -> Result<i32> {
        let oscs_list_resp = self
            .get_list_resp(OSCS_PAGE_DEFAULT, OSCS_PER_PAGE_DEFAULT)
            .await?;
        let total = oscs_list_resp.data.total;
        if total <= 0 {
            return Err(Error::Message("oscs get total error".to_owned()));
        }
        let page_count = total / OSCS_PAGE_SIZE;
        if page_count == 0 {
            return Ok(1);
        }
        if total % page_count != 0 {
            return Ok(page_count + 1);
        }
        Ok(page_count)
    }

    pub async fn parse_page(&self, page: i32) -> Result<Vec<VulnInfo>> {
        let oscs_list_resp = self.get_list_resp(page, OSCS_PAGE_SIZE).await?;
        let mut res = Vec::with_capacity(oscs_list_resp.data.data.len());
        for item in oscs_list_resp.data.data {
            let mut tags = Vec::new();
            if item.is_push == 1 {
                tags.push("发布预警".to_string());
            }
            let event_type = self.get_event_type(item.intelligence_type);
            tags.push(event_type);

            let vuln_info = self.parse_detail(&item.mps).await;
            match vuln_info {
                Ok(mut vuln) => {
                    vuln.tags = tags;
                    res.push(vuln)
                }
                Err(e) => {
                    error!("oscs parse {} detail error: {}", &item.mps, e.to_string());
                    continue;
                }
            }
        }
        Ok(res)
    }

    pub async fn parse_detail(&self, mps: &str) -> Result<VulnInfo> {
        let detail = self.get_detail_resp(mps).await?;
        if detail.code != 200 || !detail.success || detail.data.is_empty() {
            return Err(Error::Message(format!("oscs get: {} detail error", mps)));
        };
        let data = detail.data[0].clone();
        let severity = self.get_severity(&data.level);
        let disclosure = timestamp_to_date(data.publish_time)?;
        let references = data
            .references
            .iter()
            .map(|r| r.url.clone())
            .collect::<Vec<_>>();

        let solutions = self.get_solutions(data.soulution_data);

        let data = VulnInfo {
            unique_key: data.vuln_no,
            title: data.vuln_title,
            description: data.description,
            severity,
            cve: data.cve_id,
            disclosure,
            references,
            solutions,
            from: self.link.clone(),
            tags: vec![],
            reasons: vec![],
        };
        Ok(data)
    }

    pub fn get_solutions(&self, solutions: Vec<String>) -> String {
        solutions
            .iter()
            .enumerate()
            .map(|(index, item)| format!("{}.{}.\n", index + 1, item))
            .collect::<Vec<_>>()
            .join("")
    }

    fn get_event_type(&self, intelligence_type: i32) -> String {
        match intelligence_type {
            1 => "公开漏洞".to_string(),
            2 => "墨菲安全独家".to_string(),
            3 => "投毒情报".to_string(),
            _ => "公开漏洞".to_string(),
        }
    }

    async fn get_detail_resp(&self, mps: &str) -> Result<OscsDetailResp> {
        let params = serde_json::json!({
            "vuln_no": mps,
        });
        let detail: OscsDetailResp = self
            .help
            .post_json(OSCS_DETAIL_URL, &params)
            .await?
            .json()
            .await?;
        Ok(detail)
    }

    fn get_severity(&self, level: &str) -> Severity {
        match level {
            "Critical" => Severity::Critical,
            "High" => Severity::High,
            "Medium" => Severity::Medium,
            "Low" => Severity::Low,
            _ => Severity::Low,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OscsListResp {
    pub success: bool,
    pub code: i32,
    pub time: i32,
    pub info: String,
    pub data: OscsData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OscsData {
    pub total: i32,
    pub data: Vec<OscsItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OscsItem {
    pub id: String,
    pub title: String,
    pub url: String,
    pub mps: String,
    pub public_time: DateTime<FixedOffset>,
    pub intelligence_type: i32,
    pub is_push: i8,
    pub is_poc: i8,
    pub is_exp: i8,
    pub level: String,
    pub created_at: DateTime<FixedOffset>,
    pub updated_at: DateTime<FixedOffset>,
    pub is_subscribe: i8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OscsDetailResp {
    pub data: Vec<OscsDetail>,
    pub success: bool,
    pub code: i32,
    pub time: i32,
    pub info: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OscsDetail {
    pub attack_vector: String,
    pub cvss_vector: String,
    pub exp: bool,
    pub exploit_requirement_cost: String,
    pub exploitability: String,
    pub scope_influence: String,
    pub source: String,
    pub vuln_type: String,
    pub cvss_score: f64,
    pub cve_id: String,
    pub vuln_cve_id: String,
    pub cnvd_id: String,
    pub is_origin: bool,
    pub languages: Vec<String>,
    pub description: String,
    pub effect: Vec<Effect>,
    pub influence: i32,
    pub level: String,
    pub patch: String,
    pub poc: bool,
    pub publish_time: i64,
    pub references: Vec<References>,
    pub suggest_level: String,
    pub vuln_suggest: String,
    pub title: String,
    pub troubleshooting: Vec<String>,
    pub vuln_title: String,
    pub vuln_code_usage: Vec<String>,
    pub vuln_no: String,
    pub soulution_data: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Effect {
    pub affected_all_version: bool,
    pub affected_version: String,
    pub effect_id: i32,
    pub java_qn_list: Vec<String>,
    pub min_fixed_version: String,
    pub name: String,
    pub solutions: Vec<Solutions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Solutions {
    pub compatibility: i32,
    pub description: String,
    pub r#type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct References {
    pub name: String,
    pub url: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_page_count() -> Result<()> {
        let oscs = OscCrawler::new();
        let count = oscs.get_page_count().await?;
        assert!(count > 0);
        Ok(())
    }

    #[tokio::test]
    async fn test_get_list_resp() -> Result<()> {
        let oscs = OscCrawler::new();
        let res = oscs
            .get_list_resp(OSCS_PAGE_DEFAULT, OSCS_PER_PAGE_DEFAULT)
            .await?;
        assert!(res.success);
        assert_eq!(res.code, 200);
        assert_eq!(res.data.data.len(), 10);
        Ok(())
    }
}
