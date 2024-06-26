pub mod http_client;

use crate::error::{
    ChronoParseErrSnafu, CryptoSnafu, DateTimeFromTimestampErrSnafu, Result, TeraErrSnafu,
};
use chrono::{DateTime, Duration, Local, NaiveDate, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use snafu::{OptionExt, ResultExt};
use tera::{Context, Tera};

pub fn get_last_year_data() -> String {
    let current_date = Local::now();
    let last_year = current_date - Duration::days(365);
    last_year.format("%Y-%m-%d").to_string()
}

pub fn check_over_two_week(date: &str) -> Result<bool> {
    let target_date = NaiveDate::parse_from_str(date, "%Y-%m-%d")
        .with_context(|_| ChronoParseErrSnafu { date })?;
    let now = Utc::now().naive_utc().date();
    let two_weeks_ago = now - Duration::weeks(2);
    if target_date >= two_weeks_ago && target_date <= now {
        return Ok(false);
    }
    Ok(true)
}

// data_str_format convernt 20240603 to 2024-06-03
pub fn data_str_format(date: &str) -> Result<String> {
    let date =
        NaiveDate::parse_from_str(date, "%Y%m%d").with_context(|_| ChronoParseErrSnafu { date })?;
    let formatted_date = format!("{}", date.format("%Y-%m-%d"));
    Ok(formatted_date)
}

pub fn timestamp_to_date(timestamp: i64) -> Result<String> {
    let dt = DateTime::from_timestamp_millis(timestamp);
    let res = dt.with_context(|| DateTimeFromTimestampErrSnafu { timestamp })?;
    Ok(res.format("%Y-%m-%d").to_string())
}

pub fn render_string(tera_template: &str, locals: &serde_json::Value) -> Result<String> {
    Tera::one_off(
        tera_template,
        &Context::from_serialize(locals).with_context(|_| TeraErrSnafu)?,
        false,
    )
    .with_context(|_| TeraErrSnafu)
}

pub fn calc_hmac_sha256(key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).with_context(|_| CryptoSnafu)?;
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

    #[test]
    pub fn test_check_over_two_week() -> Result<()> {
        let now = Utc::now().naive_utc().date();
        let one_weeks_ago = now - Duration::weeks(1);
        let data_str = one_weeks_ago.format("%Y-%m-%d").to_string();
        let res = check_over_two_week(&data_str)?;
        assert!(!res);
        let res = check_over_two_week("2024-05-03")?;
        assert!(res);
        Ok(())
    }
}
