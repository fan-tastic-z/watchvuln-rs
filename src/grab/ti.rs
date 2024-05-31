use async_trait::async_trait;
use reqwest::header::{self};
use serde::{Deserialize, Serialize};

use super::{Grab, Provider, Severity, VulnInfo};
use crate::error::Result;
use crate::utils::http_client::Help;

const ONE_URL: &str = "https://ti.qianxin.com/alpha-api/v2/vuln/one-day";

pub struct TiCrawler {
    pub name: String,
    pub display_name: String,
    pub link: String,
    pub help: Help,
}

#[async_trait]
impl Grab for TiCrawler {
    async fn get_update(&self, _page_limit: i32) -> Result<Vec<VulnInfo>> {
        self.get_vuln_infos().await
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

impl Default for TiCrawler {
    fn default() -> Self {
        Self::new()
    }
}

impl TiCrawler {
    pub fn new() -> TiCrawler {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            "Referer",
            header::HeaderValue::from_static("https://ti.qianxin.com/"),
        );
        headers.insert(
            "Origin",
            header::HeaderValue::from_static("https://ti.qianxin.com/"),
        );

        let help = Help::new(headers);
        TiCrawler {
            name: "qianxin-ti".to_string(),
            display_name: "奇安信威胁情报中心".to_string(),
            link: "https://ti.qianxin.com/".to_string(),
            help,
        }
    }

    pub async fn get_ti_one_day_resp(&self) -> Result<TiOneDayResp> {
        let params = serde_json::json!({});
        let resp: TiOneDayResp = self.help.post_json(ONE_URL, &params).await?.json().await?;
        Ok(resp)
    }

    pub async fn get_vuln_infos(&self) -> Result<Vec<VulnInfo>> {
        let ti_one_day_resp = self.get_ti_one_day_resp().await?;
        let mut vuln_infos = Vec::with_capacity(ti_one_day_resp.data.key_vuln_add.len());
        for detail in ti_one_day_resp.data.key_vuln_add {
            let tags = self.get_tags(detail.tag);
            let severity = self.get_severity(detail.rating_level);
            let is_valuable = severity == Severity::High || severity == Severity::Critical;

            let vuln_info = VulnInfo {
                unique_key: detail.qvd_code,
                title: detail.vuln_name,
                description: detail.description,
                severity,
                cve: detail.cve_code,
                disclosure: detail.publish_time,
                references: vec![],
                solutions: "".to_string(),
                from: format!("https://ti.qianxin.com/vulnerability/detail/{}", detail.id),
                tags,
                reasons: vec![],
                is_valuable,
            };
            if vuln_infos
                .iter()
                .any(|v: &VulnInfo| v.unique_key == vuln_info.unique_key)
            {
                continue;
            }
            vuln_infos.push(vuln_info);
        }
        Ok(vuln_infos)
    }

    pub fn get_tags(&self, detail_tags: Vec<Tag>) -> Vec<String> {
        let mut tags = Vec::with_capacity(detail_tags.len());
        for tag in detail_tags {
            tags.push(tag.name.trim().to_string());
        }
        tags
    }

    pub fn get_severity(&self, detail_severity: String) -> Severity {
        let severity = match detail_severity.as_str() {
            "低危" => Severity::Low,
            "中危" => Severity::Medium,
            "高危" => Severity::High,
            "极危" => Severity::Critical,
            _ => Severity::Low,
        };
        severity
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TiOneDayResp {
    pub status: i32,
    pub message: String,
    pub data: Data,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Data {
    pub vuln_add_count: i32,
    pub vuln_update_count: i32,
    pub key_vuln_add_count: i32,
    pub poc_exp_add_count: i32,
    pub patch_add_count: i32,
    pub key_vuln_add: Vec<TiVulnDetail>,
    pub poc_exp_add: Vec<TiVulnDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TiVulnDetail {
    pub id: i32,
    pub vuln_name: String,
    pub vuln_name_en: String,
    pub qvd_code: String,
    pub cve_code: String,
    pub cnvd_id: Option<String>,
    pub cnnvd_id: Option<String>,
    pub threat_category: String,
    pub technical_category: String,
    pub residence_id: Option<i32>,
    pub rating_id: Option<i32>,
    pub not_show: i32,
    pub publish_time: String,
    pub description: String,
    pub description_en: String,
    pub change_impact: i32,
    pub operator_hid: String,
    pub create_hid: Option<String>,
    pub channel: Option<String>,
    pub tracking_id: Option<String>,
    pub temp: i32,
    pub other_rating: i32,
    pub create_time: String,
    pub update_time: String,
    pub latest_update_time: String,
    pub rating_level: String,
    pub vuln_type: String,
    pub poc_flag: i32,
    pub patch_flag: i32,
    pub detail_flag: i32,
    pub tag: Vec<Tag>,
    pub tag_len: i32,
    pub is_rating_level: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    pub name: String,
    pub font_color: String,
    pub back_color: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    pub async fn test_get_ti_one_day_resp() -> Result<()> {
        let ti = TiCrawler::new();
        let res = ti.get_ti_one_day_resp().await?;
        assert_eq!(res.status, 10000);
        Ok(())
    }
}
