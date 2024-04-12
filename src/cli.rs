use clap::Parser;

use crate::environment::DEFAULT_ENVIRONMENT;

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[arg(
        long = "dt",
        required = true,
        help = "webhook access token of dingding bot"
    )]
    pub ding_access_token: String,
    #[arg(long = "ds", required = true, help = "sign secret of dingding bot")]
    pub ding_sign_scret: String,
    /// Specify the environment
    #[arg(short, long, global = true, help = &format!("Specify the environment [default: {}]", DEFAULT_ENVIRONMENT))]
    pub environment: Option<String>,
}
