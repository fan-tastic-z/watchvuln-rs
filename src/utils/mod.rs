pub mod http_client;

use crate::{Error, Result};
use chrono::DateTime;
use tera::{Context, Tera};

pub fn timestamp_to_date(timestamp: i64) -> Result<String> {
    let dt = DateTime::from_timestamp(timestamp, 0);
    if let Some(dt) = dt {
        return Ok(dt.format("%Y-%m-%d").to_string());
    }
    Err(Error::Message("convert timestamp to date error".to_owned()))
}

pub fn render_string(tera_template: &str, locals: &serde_json::Value) -> Result<String> {
    let text = Tera::one_off(tera_template, &Context::from_serialize(locals)?, false)?;
    Ok(text)
}
