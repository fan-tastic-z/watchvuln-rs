pub mod http_client;

use crate::{Error, Result};
use chrono::DateTime;
use tera::{Context, Tera};

pub fn timestamp_to_date(timestamp: i64) -> Result<String> {
    let dt = DateTime::from_timestamp_millis(timestamp);
    if let Some(dt) = dt {
        return Ok(dt.format("%Y-%m-%d").to_string());
    }
    Err(Error::Message("convert timestamp to date error".to_owned()))
}

pub fn render_string(tera_template: &str, locals: &serde_json::Value) -> Result<String> {
    let text = Tera::one_off(tera_template, &Context::from_serialize(locals)?, false)?;
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_timestamp_to_date() {
        let res = timestamp_to_date(1715931545000).unwrap();
        assert_eq!(res, "2024-05-17");
    }
}
