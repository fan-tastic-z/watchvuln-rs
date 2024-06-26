use crate::error::{HttpClientErrSnafu, Result};
use reqwest::header::{self, HeaderMap};
use snafu::ResultExt;

#[derive(Debug, Clone)]
pub struct Help {
    pub http_client: reqwest::Client,
}

impl Default for Help {
    fn default() -> Self {
        let headers = header::HeaderMap::new();
        Self::new(headers)
    }
}
impl Help {
    pub fn new(mut headers: HeaderMap) -> Self {
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

    pub async fn get_json(&self, url: &str) -> Result<reqwest::Response> {
        let content = self
            .http_client
            .get(url)
            .send()
            .await
            .with_context(|_| HttpClientErrSnafu { url })?;
        Ok(content)
    }

    pub async fn get_html_content(&self, url: &str) -> Result<String> {
        let send_res = self
            .http_client
            .get(url)
            .send()
            .await
            .with_context(|_| HttpClientErrSnafu { url })?;

        let content = send_res
            .text()
            .await
            .with_context(|_| HttpClientErrSnafu { url })?;
        Ok(content)
    }

    pub async fn post_json<Body>(&self, url: &str, body: &Body) -> Result<reqwest::Response>
    where
        Body: serde::Serialize,
    {
        let content = self
            .http_client
            .post(url)
            .json(body)
            .send()
            .await
            .with_context(|_| HttpClientErrSnafu { url })?;
        Ok(content)
    }
}
