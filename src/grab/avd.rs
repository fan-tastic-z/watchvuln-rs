use eyre::eyre;
use regex::Regex;
use scraper::{Html, Selector};

use crate::{Error, Result};

const PAGE_REGEXP: &str = r"第 \d+ 页 / (\d+) 页 ";
// const CVEID_REGEXP: &str = r"^CVE-\d+-\d+$";

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

        let _detail_links = document
            .select(&src_url_selector)
            .filter_map(|a| a.value().attr("href"))
            .collect::<Vec<_>>();

        Ok(())
    }

    pub async fn parse_detail_page(&self, href: &str) -> Result<()> {
        let detail_url = format!("https://avd.aliyun.com{}", href);
        let _content = self
            .http_client
            .get(detail_url)
            .send()
            .await?
            .text()
            .await?;

        Ok(())
    }
}
