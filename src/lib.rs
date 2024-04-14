pub mod cli;
pub mod config;
pub mod environment;
pub mod error;
pub mod grab;
pub mod logger;
pub mod tera;

use std::{sync::Arc, time::Duration};

pub use cli::Cli;
use config::Config;
use environment::Environment;
pub use error::Error;
use tokio::time;
use tokio_cron_scheduler::{Job, JobScheduler};

use crate::grab::AVDCrawler;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone)]
pub struct AppContext {
    pub environment: Environment,
    pub config: Config,
}

pub async fn create_context(environment: &Environment) -> Result<AppContext> {
    let config = environment.load()?;
    Ok(AppContext {
        environment: environment.clone(),
        config,
    })
}

pub async fn run_app(app_context: Arc<AppContext>) -> Result<()> {
    let sched = JobScheduler::new().await?;
    let job = Job::new_async("0 */1 1-22 * * *", move |_uuid, _lock| {
        let app_context_cloned = app_context.clone();
        Box::pin(async move {
            let res = my_task(app_context_cloned).await;
            println!("res is {:?}", res)
        })
    })?;

    sched.add(job).await?;
    sched.start().await?;
    loop {
        time::sleep(Duration::from_secs(10)).await;
    }
}

async fn my_task(app_context: Arc<AppContext>) -> Result<()> {
    tracing::info!("{:?}", app_context.config);

    tracing::info!("Executing task...");
    let avd = AVDCrawler::new();
    avd.get_update(1).await?;
    Ok(())
}
