use clap::Parser;
use watchvuln_rs::environment::{resolve_from_env, Environment};
use watchvuln_rs::run_app;
use watchvuln_rs::{create_context, Cli, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let cli: Cli = Cli::parse();
    let environment: Environment = cli.environment.unwrap_or_else(resolve_from_env).into();
    let app_context = create_context(&environment).await?;
    run_app(app_context).await?;
    Ok(())
}
