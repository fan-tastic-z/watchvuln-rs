use eyre::eyre;
use regex::Regex;
use reqwest::Url;
use scraper::{Html, Selector};
use tracing::warn;

use crate::{
    grab::{Severity, VulnInfo},
    Error, Result,
};

const PAGE_REGEXP: &str = r"第 \d+ 页 / (\d+) 页 ";
const CVEID_REGEXP: &str = r"^CVE-\d+-\d+$";

pub struct AVDCrawler {
    pub name: String,
    pub display_name: String,
    pub link: String,
    pub http_client: reqwest::Client,
}

impl Default for AVDCrawler {
    fn default() -> Self {
        Self::new()
    }
}

impl AVDCrawler {
    pub fn new() -> AVDCrawler {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .cookie_store(true)
            .build()
            .unwrap();
        AVDCrawler {
            name: "aliyun-avd".to_string(),
            display_name: "阿里云漏洞库".to_string(),
            link: "https://avd.aliyun.com/high-risk/list".to_string(),
            http_client: client,
        }
    }

    pub async fn get_update(&self, page_limit: i32) -> Result<()> {
        let mut page_count = self.get_page_count().await?;
        if page_count > page_limit {
            page_count = page_limit;
        }
        if let Some(i) = (1..=page_count).next() {
            println!("{}", i);
            self.parse_page(i).await?;
        }
        Ok(())
    }

    pub async fn get_page_count(&self) -> Result<i32> {
        let content = self
            .http_client
            .get(&self.link)
            .send()
            .await?
            .text()
            .await?;
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

    pub async fn parse_page(&self, page: i32) -> Result<()> {
        let page_url = format!("{}?page={}", self.link, page);
        let content = self.http_client.get(&page_url).send().await?.text().await?;
        let document = Html::parse_document(&content);
        let src_url_selector =
            Selector::parse("tbody tr td a").map_err(|err| eyre!("parse html error {}", err))?;

        let detail_links = document
            .select(&src_url_selector)
            .filter_map(|a| a.value().attr("href"))
            .collect::<Vec<_>>();
        let mut res = Vec::with_capacity(detail_links.len());
        for detail in detail_links {
            println!("{}", detail);
            let data = self.parse_detail_page(detail.as_ref()).await?;
            res.push(data)
        }
        println!("{:?}", res);
        Ok(())
    }

    pub async fn parse_detail_page(&self, href: &str) -> Result<VulnInfo> {
        println!("parsing vuln {}", href);
        let detail_url = format!("https://avd.aliyun.com{}", href);
        let content = self
            .http_client
            .get(&detail_url)
            .send()
            .await?
            .text()
            .await?;
        let url = Url::parse(&detail_url)?;
        let avd_id = url
            .query_pairs()
            .filter(|(key, _)| key == "id")
            .map(|(_, value)| value)
            .collect::<Vec<_>>();
        let avd_id = avd_id[0].to_string();
        let mut title = "".to_string();
        let mut level = "".to_string();
        let mut cve_id = "".to_string();
        let mut disclosure = "".to_string();
        let mut tags = Vec::new();
        let document = Html::parse_document(&content);
        let metric_selector = Selector::parse("div[class='metric']")
            .map_err(|err| eyre!("parse html error {}", err))?;
        let elements = document.select(&metric_selector);
        for e in elements {
            let label_selector = Selector::parse(".metric-label")
                .map_err(|err| eyre!("parse html error {}", err))?;
            let value_selector = Selector::parse(".metric-value")
                .map_err(|err| eyre!("parse html error {}", err))?;
            let label_element = e
                .select(&label_selector)
                .next()
                .ok_or(eyre!("find label element error"))?;
            let value_element = e
                .select(&value_selector)
                .next()
                .ok_or(eyre!("find value element error"))?;
            let label_text = label_element.inner_html();
            let value_text = value_element.inner_html();
            if label_text.contains("CVE") {
                cve_id = value_text.to_string();
            } else if label_text.contains("利用情况") {
                if value_text != "暂无" {
                    tags.push(value_text.to_string());
                }
            } else if label_text.contains("披露时间") {
                disclosure = value_text.to_string();
            }
        }

        if !Regex::new(CVEID_REGEXP)?.is_match(&cve_id) {
            warn!("cve id not found in {}", href);
            cve_id = "".to_string();
        }
        if cve_id.is_empty() && disclosure.is_empty() {
            return Err(eyre!("invalid vuln data in {}", href).into());
        }

        let level_selector = Selector::parse("h5[class='header__title'] .badge")
            .map_err(|err| eyre!("parse html error {}", err))?;
        let header_elements = document
            .select(&level_selector)
            .map(|s| s.inner_html())
            .collect::<Vec<_>>();
        if header_elements.len() == 1 {
            level = header_elements[0].clone();
        }

        let text_selector = Selector::parse("h5[class='header__title'] .header__title__text")
            .map_err(|err| eyre!("parse html error {}", err))?;
        let text_elements = document
            .select(&text_selector)
            .map(|s| s.inner_html())
            .collect::<Vec<_>>();
        if text_elements.len() == 1 {
            title = text_elements[0].clone();
        }

        let description_selector =
            Selector::parse(".text-detail div").map_err(|err| eyre!("parse html error {}", err))?;
        let description = document
            .select(&description_selector)
            .map(|e| e.text().collect::<String>())
            .collect::<Vec<String>>()
            .join("\n");

        let fix_step_selector =
            Selector::parse(".text-detail").map_err(|err| eyre!("parse html error {}", err))?;
        let solutions = document
            .select(&fix_step_selector)
            .nth(1)
            .unwrap()
            .text()
            .map(|el| el.trim())
            .map(|el| el.trim_matches('"'))
            .collect::<Vec<_>>()
            .join("\n");

        let reference_selector = Selector::parse("td[nowrap='nowrap'] a").unwrap();
        let references = document
            .select(&reference_selector)
            .filter_map(|el| el.attr("href"))
            .map(|e| e.to_string())
            .collect::<Vec<_>>();
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
}

#[cfg(test)]
mod tests {
    use std::fs;

    use scraper::{Html, Selector};

    fn get_html_content() -> String {
        fs::read_to_string("tests/html/avd_detail.html").unwrap()
    }

    #[test]
    fn test_get_fix_step() {
        let content = &get_html_content();
        let document = Html::parse_document(content);
        let fix_step_selector = Selector::parse(".text-detail").unwrap();
        let e = document
            .select(&fix_step_selector)
            .nth(1)
            .unwrap()
            .text()
            .map(|el| el.trim())
            .collect::<Vec<_>>()
            .join("\n");
        println!("{:?}", e);
    }

    #[test]
    fn test_get_reference() {
        let content = &get_html_content();
        let document = Html::parse_document(content);
        let reference_selector = Selector::parse("td[nowrap='nowrap'] a").unwrap();
        let e = document
            .select(&reference_selector)
            .filter_map(|el| el.attr("href"))
            .collect::<Vec<_>>()
            .join("\n");
        println!("{}", e);
    }
}
