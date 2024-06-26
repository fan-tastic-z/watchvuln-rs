use std::{num::ParseIntError, time::SystemTimeError};

use hmac::digest::crypto_common;
use macros::stack_trace_debug;
use migration::sea_orm;
use scraper::error::SelectorErrorKind;
use snafu::{Location, Snafu};

pub type Result<T, E = AppError> = std::result::Result<T, E>;

#[derive(Snafu)]
#[snafu(visibility(pub))]
#[stack_trace_debug]
pub enum AppError {
    #[snafu(display("IO error"))]
    Io {
        #[snafu(source)]
        error: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("db error"))]
    DbErr {
        #[snafu(source)]
        error: sea_orm::DbErr,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("db table {} filter by {} not found", table, filter))]
    DbNotFoundErr {
        table: String,
        filter: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("db table {} filter by {} altread exists", table, filter))]
    DbAlreadyExists {
        table: String,
        filter: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("cron scheduler error"))]
    CronSchedulerErr {
        #[snafu(source)]
        error: tokio_cron_scheduler::JobSchedulerError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("request url {url} error"))]
    HttpClientErr {
        url: String,
        #[snafu(source)]
        error: reqwest::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("regex new {re} error"))]
    RegexErr {
        re: String,
        #[snafu(source)]
        error: regex::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("regex captures error: {msg}"))]
    RegexCapturesErr {
        msg: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("parse {num} to int error"))]
    ParseIntErr {
        num: String,
        #[snafu(source)]
        error: ParseIntError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("parse {url} error"))]
    ParseUrlErr {
        url: String,
        #[snafu(source)]
        error: url::ParseError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("task join error"))]
    TaskJoinErr {
        #[snafu(source)]
        error: tokio::task::JoinError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("tera error"))]
    TeraErr {
        #[snafu(source)]
        error: tera::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("crypto error"))]
    CryptoError {
        #[snafu(source)]
        error: crypto_common::InvalidLength,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("json error"))]
    JsonErr {
        #[snafu(source)]
        error: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("teloxide request error"))]
    TeloxideErr {
        #[snafu(source)]
        error: teloxide::RequestError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("octocrab search {search} error"))]
    OctocrabErr {
        search: String,
        #[snafu(source)]
        error: octocrab::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("chrono parse {date} error"))]
    ChronoParseErr {
        date: String,
        #[snafu(source)]
        error: chrono::ParseError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("system time error"))]
    SystemTimeErr {
        #[snafu(source)]
        error: SystemTimeError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Illegal config msg: {msg}"))]
    ConfigErr {
        msg: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("serde yaml error"))]
    SerdeYamlErr {
        #[snafu(source)]
        error: serde_yaml::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("timestamp {timestamp} to datetime error"))]
    DateTimeFromTimestampErr {
        timestamp: i64,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("scraper selector error"))]
    SelectorError {
        #[snafu(source)]
        error: SelectorErrorKind<'static>,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("html selector nth {} not found", nth))]
    SelectNthErr {
        nth: usize,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("html element attr {} not found", attr))]
    ElementAttrErr {
        attr: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("ding push markdown message response errorcode {errorcode}"))]
    DingPushErr {
        errorcode: i64,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("lark push markdown message response code {code}"))]
    LarkPushErr {
        code: i64,
        #[snafu(implicit)]
        location: Location,
    },

    // detail.code != 200 || !detail.success || detail.data.is_empty(),
    #[snafu(display("oscs {mps} detail {code} invalid"))]
    InvalidOscsDetail {
        mps: String,
        code: i64,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("oscs list total invalid"))]
    InvalidOscsListTotal {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("seebug parse html error"))]
    ParseSeeBugHtmlErr {
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Invalid seebug page num: {}", num))]
    InvalidSeebugPageNum {
        num: usize,
        #[snafu(implicit)]
        location: Location,
    },
}
