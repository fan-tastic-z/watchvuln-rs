pub mod cli;
pub mod config;
pub mod environment;
pub mod error;
pub mod tera;

use std::time::Duration;

pub use cli::Cli;
use config::Config;
use environment::Environment;
pub use error::Error;
use tokio::time;
use tokio_cron_scheduler::{Job, JobScheduler};

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

pub async fn run_app(app_context: AppContext) -> Result<()> {
    println!("{:?}", app_context.config);
    let sched = JobScheduler::new().await?;
    let job = Job::new_async("0 */1 7-22 * * *", |_uuid, _lock| {
        Box::pin(async move {
            my_task().await;
        })
    })?;

    sched.add(job).await?;
    sched.start().await?;
    loop {
        time::sleep(Duration::from_secs(10)).await;
    }
}

async fn my_task() {
    println!("Executing task...");
}
