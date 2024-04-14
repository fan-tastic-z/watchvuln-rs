use eyre::eyre;
use regex::Regex;
use reqwest::Url;
use scraper::{Html, Selector};
use tracing::warn;

use crate::{
    grab::{Severity, VulnInfo},
    help::Help,
    Error, Result,
};

const PAGE_REGEXP: &str = r"第 \d+ 页 / (\d+) 页 ";
const CVEID_REGEXP: &str = r"^CVE-\d+-\d+$";

pub struct AVDCrawler {
    pub name: String,
    pub display_name: String,
    pub link: String,
    pub help: Help,
}

impl Default for AVDCrawler {
    fn default() -> Self {
        Self::new()
    }
}

impl AVDCrawler {
    pub fn new() -> AVDCrawler {
        let help = Help::new();
        AVDCrawler {
            name: "aliyun-avd".to_string(),
            display_name: "阿里云漏洞库".to_string(),
            link: "https://avd.aliyun.com/high-risk/list".to_string(),
            help,
        }
    }

    pub async fn get_update(&self, page_limit: i32) -> Result<Vec<VulnInfo>> {
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

    pub async fn get_page_count(&self) -> Result<i32> {
        let content = self.help.get_html_content(&self.link).await?;
        let cap = Regex::new(PAGE_REGEXP)?.captures(&content);
        if let Some(res) = cap {
            if res.len() == 2 {
                let total = res[1].parse::<i32>()?;
                Ok(total)
            } else {
                Err(Error::Message("page regex match error".to_owned()))
            }
        } else {
            Err(Error::Message("page regex match not found".to_owned()))
        }
    }

    pub async fn parse_page(&self, page: i32) -> Result<Vec<VulnInfo>> {
        let page_url = format!("{}?page={}", self.link, page);
        let content = self.help.get_html_content(&page_url).await?;
        let document = Html::parse_document(&content);
        let detail_links = self.get_detail_links(document)?;
        let mut res = Vec::with_capacity(detail_links.len());
        for detail in detail_links {
            let data = self.parse_detail_page(detail.as_ref()).await?;
            res.push(data)
        }
        Ok(res)
    }

    fn get_detail_links(&self, document: Html) -> Result<Vec<String>> {
        let src_url_selector =
            Selector::parse("tbody tr td a").map_err(|err| eyre!("parse html error {}", err))?;

        let detail_links: Vec<String> = document
            .select(&src_url_selector)
            .filter_map(|a| a.value().attr("href"))
            .map(|l| l.to_string())
            .collect();
        Ok(detail_links)
    }

    pub async fn parse_detail_page(&self, href: &str) -> Result<VulnInfo> {
        println!("parsing vuln {}", href);
        let detail_url = format!("https://avd.aliyun.com{}", href);
        let content = self.help.get_html_content(&detail_url).await?;
        let url = Url::parse(&detail_url)?;
        let avd_id = url
            .query_pairs()
            .filter(|(key, _)| key == "id")
            .map(|(_, value)| value)
            .collect::<Vec<_>>();
        let avd_id = avd_id[0].to_string();
        let mut tags = Vec::new();
        let document = Html::parse_document(&content);

        let mut cve_id = self.get_cve_id(&document)?;
        let utilization = self.get_utilization(&document)?;
        let disclosure = self.get_disclosure(&document)?;
        if utilization != "暂无" {
            tags.push(utilization);
        }

        if !Regex::new(CVEID_REGEXP)?.is_match(&cve_id) {
            warn!("cve id not found in {}", href);
            cve_id = "".to_string();
        }
        if cve_id.is_empty() && disclosure.is_empty() {
            return Err(eyre!("invalid vuln data in {}", href).into());
        }

        let level = self.get_level(&document)?;

        let title = self.get_title(&document)?;

        let description = self.get_description(&document)?;

        let solutions = self.get_solutions(&document)?;

        let references = self.get_references(&document)?;

        let severity = match level.as_str() {
            "低危" => Severity::Low,
            "中危" => Severity::Medium,
            "高危" => Severity::High,
            "严重" => Severity::Critical,
            _ => Severity::Low,
        };

        let data = VulnInfo {
            unique_key: avd_id,
            title,
            description,
            severity,
            cve: cve_id,
            disclosure,
            references,
            solutions,
            from: self.link.clone(),
            tags,
        };
        Ok(data)
    }

    fn get_references(&self, document: &Html) -> Result<Vec<String>> {
        let reference_selector = Selector::parse("td[nowrap='nowrap'] a").unwrap();
        let references = document
            .select(&reference_selector)
            .filter_map(|el| el.attr("href"))
            .map(|e| e.to_string())
            .collect::<Vec<_>>();
        Ok(references)
    }

    fn get_solutions(&self, document: &Html) -> Result<String> {
        let solutions_selector =
            Selector::parse(".text-detail").map_err(|err| eyre!("parse html error {}", err))?;
        let solutions = document
            .select(&solutions_selector)
            .nth(1)
            .unwrap()
            .text()
            .map(|el| el.trim())
            .collect::<Vec<_>>()
            .join("\n");
        Ok(solutions)
    }

    fn get_description(&self, document: &Html) -> Result<String> {
        let description_selector =
            Selector::parse(".text-detail div").map_err(|err| eyre!("parse html error {}", err))?;
        let description = document
            .select(&description_selector)
            .map(|e| e.text().collect::<String>())
            .collect::<Vec<String>>()
            .join("\n");
        Ok(description)
    }

    fn get_title(&self, document: &Html) -> Result<String> {
        let title_selector = Selector::parse("h5[class='header__title'] .header__title__text")
            .map_err(|err| eyre!("parse html error {}", err))?;
        let title = document
            .select(&title_selector)
            .nth(0)
            .ok_or_else(|| eyre!("title value not found"))?
            .inner_html()
            .trim()
            .to_string();
        Ok(title)
    }

    fn get_level(&self, document: &Html) -> Result<String> {
        let level_selector = Selector::parse("h5[class='header__title'] .badge").unwrap();
        let level = document
            .select(&level_selector)
            .nth(0)
            .ok_or_else(|| eyre!("level value not found"))?
            .inner_html()
            .trim()
            .to_string();
        Ok(level)
    }

    fn get_mertric_value(&self, document: &Html, index: usize) -> Result<String> {
        let value_selector =
            Selector::parse(".metric-value").map_err(|err| eyre!("parse html error {}", err))?;
        let metric_value = document
            .select(&value_selector)
            .nth(index)
            .ok_or_else(|| eyre!("metric value not found"))?
            .inner_html()
            .trim()
            .to_string();
        Ok(metric_value)
    }

    fn get_cve_id(&self, document: &Html) -> Result<String> {
        self.get_mertric_value(document, 0)
    }

    fn get_utilization(&self, document: &Html) -> Result<String> {
        self.get_mertric_value(document, 1)
    }

    fn get_disclosure(&self, document: &Html) -> Result<String> {
        self.get_mertric_value(document, 3)
    }
}
