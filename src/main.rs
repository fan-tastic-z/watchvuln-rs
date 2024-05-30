use std::sync::Arc;

use watchvuln_rs::app::{create_context, WatchVulnApp};
use watchvuln_rs::environment::{resolve_from_env, Environment};
use watchvuln_rs::error::Result;
use watchvuln_rs::logger;

#[tokio::main]
async fn main() -> Result<()> {
    let environment: Environment = resolve_from_env().into();
    let app_context = Arc::new(create_context(&environment).await?);
    logger::init(&app_context.config.logger);
    let app = WatchVulnApp::new(app_context);
    app.run_migration().await?;
    app.run().await?;
    Ok(())
}
