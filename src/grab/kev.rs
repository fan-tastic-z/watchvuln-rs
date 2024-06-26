use async_trait::async_trait;
use chrono::{DateTime, FixedOffset};
use reqwest::header::{self};
use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use tracing::info;

use super::{Grab, VulnInfo};
use crate::error::{HttpClientErrSnafu, Result};
use crate::{grab::Severity, utils::http_client::Help};

const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const KEV_PAGE_SIZE: usize = 10;

#[derive(Default)]
pub struct KevCrawler {
    pub name: String,
    pub display_name: String,
    pub link: String,
    pub help: Help,
}

#[async_trait]
impl Grab for KevCrawler {
    async fn get_update(&self, page_limit: i32) -> Result<Vec<VulnInfo>> {
        let get_json_res = self.help.get_json(KEV_URL).await?;
        let kev_list_resp: KevResp = get_json_res
            .json()
            .await
            .with_context(|_| HttpClientErrSnafu { url: KEV_URL })?;
        let all_count = kev_list_resp.vulnerabilities.len();
        let item_limit = if page_limit as usize * KEV_PAGE_SIZE > all_count {
            all_count
        } else {
            page_limit as usize * KEV_PAGE_SIZE
        };
        let mut vulnerabilities = kev_list_resp.vulnerabilities;
        vulnerabilities.sort_by(|a, b| b.date_added.cmp(&a.date_added));
        let mut res = Vec::with_capacity(item_limit);
        for vuln in vulnerabilities.iter().take(item_limit) {
            let mut references = Vec::new();
            if !vuln.notes.is_empty() {
                references.push(vuln.notes.to_string())
            }
            let is_valuable = true;

            let vuln_info = VulnInfo {
                unique_key: format!("{}_KEV", vuln.cve_id),
                title: vuln.vulnerability_name.to_string(),
                description: vuln.short_description.to_string(),
                severity: Severity::Critical,
                cve: vuln.cve_id.to_string(),
                disclosure: vuln.date_added.to_string(),
                references,
                solutions: vuln.required_action.to_string(),
                from: self.link.to_string(),
                tags: vec![
                    vuln.vendor_project.to_string(),
                    vuln.product.to_string(),
                    "在野利用".to_string(),
                ],
                github_search: vec![],
                reasons: vec![],
                is_valuable,
                pushed: false,
            };
            res.push(vuln_info)
        }
        info!("{} crawling count {}", self.get_name(), res.len());
        Ok(res)
    }

    fn get_name(&self) -> String {
        self.display_name.to_owned()
    }
}

impl KevCrawler {
    pub fn new() -> KevCrawler {
        let headers = header::HeaderMap::new();
        let help = Help::new(headers);
        KevCrawler {
            name: "KevCrawler".to_string(),
            display_name: "Known Exploited Vulnerabilities Catalog".to_string(),
            link: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog".to_string(),
            help,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all(deserialize = "camelCase"))]
pub struct KevResp {
    pub title: String,
    pub catalog_version: String,
    pub date_released: DateTime<FixedOffset>,
    pub count: i32,
    pub vulnerabilities: Vec<Vulnerability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all(deserialize = "camelCase"))]
pub struct Vulnerability {
    #[serde(alias = "cveID")]
    pub cve_id: String,
    pub vendor_project: String,
    pub product: String,
    pub vulnerability_name: String,
    pub date_added: String,
    pub short_description: String,
    pub required_action: String,
    pub due_date: String,
    pub known_ransomware_campaign_use: String,
    pub notes: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_key_res() -> Result<()> {
        let kev = KevCrawler::new();
        let kev_list_resp: KevResp = kev
            .help
            .get_json(KEV_URL)
            .await?
            .json()
            .await
            .with_context(|_| HttpClientErrSnafu { url: KEV_URL })?;
        let mut vulnerabilities = kev_list_resp.vulnerabilities;
        vulnerabilities.sort_by(|a, b| b.date_added.cmp(&a.date_added));
        println!("{:?}", vulnerabilities);
        Ok(())
    }
}
