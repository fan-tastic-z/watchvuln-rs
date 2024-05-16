use async_trait::async_trait;
use eyre::eyre;
use scraper::{ElementRef, Html, Selector};
use tracing::warn;

use crate::grab::{Severity, VulnInfo};
use crate::utils::http_client::Help;
use crate::{Error, Result};

use super::{Grab, Provider};

pub struct SeeBugCrawler {
    pub name: String,
    pub display_name: String,
    pub link: String,
    pub help: Help,
}

#[async_trait]
impl Grab for SeeBugCrawler {
    async fn get_update(&self, page_limit: i32) -> Result<Vec<VulnInfo>> {
        let mut page_count = self.get_page_count().await?;
        if page_count > page_limit {
            page_count = page_limit;
        }
        let mut res: Vec<VulnInfo> = Vec::new();
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

impl Default for SeeBugCrawler {
    fn default() -> Self {
        Self::new()
    }
}

impl SeeBugCrawler {
    pub fn new() -> SeeBugCrawler {
        let help = Help::new();
        SeeBugCrawler {
            name: "seebug".to_string(),
            display_name: "Seebug 漏洞平台".to_string(),
            link: "https://www.seebug.org".to_string(),
            help,
        }
    }

    pub async fn get_page_count(&self) -> Result<i32> {
        let list_url = "https://www.seebug.org/vuldb/vulnerabilities";
        let content = self.help.get_html_content(list_url).await?;
        let document = Html::parse_document(&content);
        let selector = Selector::parse("ul.pagination li a")
            .map_err(|err| eyre!("parse html error {}", err))?;
        let page_nums = document
            .select(&selector)
            .map(|el| el.inner_html())
            .collect::<Vec<_>>();
        if page_nums.len() < 3 {
            return Err(Error::Message(
                "failed to get seebug pagination node".to_owned(),
            ));
        }
        let total = page_nums[page_nums.len() - 1 - 1].parse::<i32>()?;
        Ok(total)
    }

    pub async fn parse_page(&self, page: i32) -> Result<Vec<VulnInfo>> {
        let url = format!("https://www.seebug.org/vuldb/vulnerabilities?page={}", page);
        let content = self.help.get_html_content(&url).await?;
        let document = Html::parse_document(&content);
        let selector = Selector::parse(".sebug-table tbody tr")
            .map_err(|err| eyre!("parse html error {}", err))?;
        let tr_elements = document.select(&selector).collect::<Vec<_>>();
        if tr_elements.is_empty() {
            return Err(Error::Message("failed to get seebug page".into()));
        }
        let mut res = Vec::with_capacity(tr_elements.len());
        for el in tr_elements {
            let (href, unique_key) = match self.get_href(el) {
                Ok((href, unique_key)) => (href, unique_key),
                Err(e) => {
                    warn!("seebug get href error {}", e);
                    continue;
                }
            };
            let disclosure = match self.get_disclosure(el) {
                Ok(disclosure) => disclosure,
                Err(e) => {
                    warn!("seebug get disclosure error {}", e);
                    continue;
                }
            };
            let severity_title = match self.get_severity_title(el) {
                Ok(severity_title) => severity_title,
                Err(e) => {
                    warn!("seebug get severity title error {}", e);
                    continue;
                }
            };
            let title = match self.get_title(el) {
                Ok(title) => title,
                Err(e) => {
                    warn!("seebug get title error {}", e);
                    continue;
                }
            };
            let cve_id = match self.get_cve_id(el) {
                Ok(cve_id) => cve_id,
                Err(e) => {
                    warn!("seebug get cve_id error {}", e);
                    "".to_string()
                }
            };
            let tag = match self.get_tag(el) {
                Ok(tag) => tag,
                Err(e) => {
                    warn!("seebug get tag error {}", e);
                    continue;
                }
            };
            let severity = match severity_title.as_str() {
                "低危" => Severity::Low,
                "中危" => Severity::Medium,
                "高危" => Severity::High,
                _ => Severity::Low,
            };
            let mut tags = Vec::new();
            if !tag.is_empty() {
                tags.push(tag)
            }
            let data = VulnInfo {
                unique_key,
                title,
                description: "".to_owned(),
                severity,
                cve: cve_id,
                disclosure,
                references: vec![],
                solutions: "".to_owned(),
                from: href,
                tags,
                reason: vec![],
            };
            res.push(data);
        }
        Ok(res)
    }

    fn get_href(&self, el: ElementRef) -> Result<(String, String)> {
        let selector = Selector::parse("td a").map_err(|err| eyre!("parse html error {}", err))?;
        let a_element = el
            .select(&selector)
            .nth(0)
            .ok_or_else(|| eyre!("value not found"))?;
        let href = a_element
            .value()
            .attr("href")
            .ok_or_else(|| eyre!("href not found"))?
            .trim();
        let href = format!("https://www.seebug.org{}", href);
        let binding = a_element.inner_html();
        let unique_key = binding.trim();
        Ok((href.to_owned(), unique_key.to_owned()))
    }

    fn get_disclosure(&self, el: ElementRef) -> Result<String> {
        let selector = Selector::parse("td").map_err(|err| eyre!("parse html error {}", err))?;
        let disclosure = el
            .select(&selector)
            .nth(1)
            .ok_or_else(|| eyre!("value not found"))?
            .inner_html();

        Ok(disclosure)
    }

    fn get_severity_title(&self, el: ElementRef) -> Result<String> {
        let selector =
            Selector::parse("td div").map_err(|err| eyre!("parse html error {}", err))?;
        let td_element = el
            .select(&selector)
            .nth(0)
            .ok_or_else(|| eyre!("severity_title div not found"))?;
        let severity_title = td_element
            .value()
            .attr("data-original-title")
            .ok_or_else(|| eyre!("href not found"))?
            .trim();
        Ok(severity_title.to_owned())
    }

    fn get_title(&self, el: ElementRef) -> Result<String> {
        let selector = Selector::parse("td a[class='vul-title']")
            .map_err(|err| eyre!("parse html error {}", err))?;
        let title = el
            .select(&selector)
            .nth(0)
            .ok_or_else(|| eyre!("title not found"))?
            .inner_html();
        Ok(title)
    }

    fn get_cve_id(&self, el: ElementRef) -> Result<String> {
        let selector = Selector::parse("td i[class='fa fa-id-card ']")
            .map_err(|err| eyre!("parse html error {}", err))?;
        let cve_ids = el
            .select(&selector)
            .nth(0)
            .ok_or_else(|| eyre!("cve id element not found"))?
            .value()
            .attr("data-original-title")
            .ok_or_else(|| eyre!("data-original-title not found"))?
            .trim();
        let mut cve_id = "";
        if cve_ids.contains('、') {
            cve_id = cve_ids
                .split('、')
                .nth(0)
                .ok_or_else(|| eyre!("cve_ids split not found cve id"))?
        }
        Ok(cve_id.to_string())
    }

    fn get_tag(&self, el: ElementRef) -> Result<String> {
        let selector = Selector::parse("td .fa-file-text-o")
            .map_err(|err| eyre!("parse html error {}", err))?;
        let tag = el
            .select(&selector)
            .nth(0)
            .ok_or_else(|| eyre!("tag element not found"))?
            .value()
            .attr("data-original-title")
            .ok_or_else(|| eyre!("tag data-original-title not found"))?
            .trim();
        Ok(tag.to_string())
    }
}