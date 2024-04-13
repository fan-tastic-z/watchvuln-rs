use std::sync::Arc;

use clap::Parser;
use watchvuln_rs::environment::{resolve_from_env, Environment};
use watchvuln_rs::{create_context, Cli, Result};
use watchvuln_rs::{logger, run_app};

#[tokio::main]
async fn main() -> Result<()> {
    let cli: Cli = Cli::parse();
    let environment: Environment = cli.environment.unwrap_or_else(resolve_from_env).into();
    let app_context = Arc::new(create_context(&environment).await?);
    logger::init(&app_context.config.logger);
    run_app(app_context).await?;
    Ok(())
}
