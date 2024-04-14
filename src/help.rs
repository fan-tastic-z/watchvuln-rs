use reqwest::header;

use crate::Result;

pub struct Help {
    pub http_client: reqwest::Client,
}

impl Default for Help {
    fn default() -> Self {
        Self::new()
    }
}
impl Help {
    pub fn new() -> Self {
        let mut headers = header::HeaderMap::new();
        headers.insert("User-Agent", header::HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"));
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(true)
            .default_headers(headers)
            .build()
            .unwrap();
        Help {
            http_client: client,
        }
    }

    pub async fn get_html_content(&self, url: &str) -> Result<String> {
        let content = self.http_client.get(url).send().await?.text().await?;
        Ok(content)
    }
}
