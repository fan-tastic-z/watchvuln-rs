pub mod http_client;

use crate::error::{Error, Result};
use chrono::{DateTime, Duration, Local, NaiveDate, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tera::{Context, Tera};

pub fn get_last_year_data() -> String {
    let current_date = Local::now();
    let last_year = current_date - Duration::days(365);
    last_year.format("%Y-%m-%d").to_string()
}

pub fn check_over_two_week(date: &str) -> Result<bool> {
    let target_date = NaiveDate::parse_from_str(date, "%Y-%m-%d")?;
    let now = Utc::now().naive_utc().date();
    let two_weeks_ago = now - Duration::weeks(2);
    if target_date >= two_weeks_ago && target_date <= now {
        return Ok(false);
    }
    Ok(true)
}

// data_str_format convernt 20240603 to 2024-06-03
pub fn data_str_format(date: &str) -> Result<String> {
    let date = NaiveDate::parse_from_str(date, "%Y%m%d")?;
    let formatted_date = format!("{}", date.format("%Y-%m-%d"));
    Ok(formatted_date)
}

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

pub fn calc_hmac_sha256(key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
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
