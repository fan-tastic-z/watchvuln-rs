pub mod config;
pub mod db;
pub mod environment;
pub mod error;
pub mod grab;
pub mod logger;
pub mod models;
pub mod utils;

use std::{collections::HashMap, sync::Arc, time::Duration};

use config::Config;
use environment::Environment;
pub use error::Error;
use migration::sea_orm::DatabaseConnection;
use tokio::{task::JoinSet, time};
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::{info, warn};

use crate::{grab::Grab, models::_entities::vuln_informations};

const PAGE_LIMIT: i32 = 1;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Debug)]
pub struct AppContext {
    pub environment: Environment,
    pub config: Config,
    pub db: DatabaseConnection,
}

pub async fn create_context(environment: &Environment) -> Result<AppContext> {
    let config = environment.load()?;
    let db = db::connect(&config.database).await?;
    Ok(AppContext {
        environment: environment.clone(),
        config,
        db,
    })
}

#[derive(Debug, Clone)]
pub struct WatchVulnApp {
    pub app_context: Arc<AppContext>,
}

impl WatchVulnApp {
    pub fn new(app_context: Arc<AppContext>) -> Self {
        WatchVulnApp { app_context }
    }

    pub async fn run(&self) -> Result<()> {
        let self_arc = Arc::new(self.clone());
        let sched = JobScheduler::new().await?;
        let job = Job::new_async("0 */1 1-23 * * *", move |_uuid, _lock| {
            let self_clone = self_arc.clone();
            Box::pin(async move {
                let res = self_clone.my_task().await;
                info!("crawling over, result is : {:#?}", res);
            })
        })?;

        sched.add(job).await?;
        sched.start().await?;
        loop {
            time::sleep(Duration::from_secs(10)).await;
        }
    }

    async fn my_task(&self) -> Vec<vuln_informations::Model> {
        tracing::info!("{:?}", self.app_context.config);
        let grab_manager = grab::init();
        let map: HashMap<String, Arc<Box<dyn Grab>>> = grab_manager
            .map
            .into_iter()
            .map(|(k, v)| (k, Arc::new(v)))
            .collect();

        let mut set = JoinSet::new();
        for (_, v) in map.into_iter() {
            let grab = v.clone();
            set.spawn(async move { grab.get_update(PAGE_LIMIT).await });
        }
        let mut new_vulns = Vec::new();
        while let Some(set_res) = set.join_next().await {
            match set_res {
                Ok(grabs_res) => match grabs_res {
                    Ok(res) => {
                        for v in res {
                            let create_res =
                                vuln_informations::Model::creat_or_update(&self.app_context.db, v)
                                    .await;
                            match create_res {
                                Ok(m) => {
                                    info!("found new vuln:{}", m.key);
                                    new_vulns.push(m)
                                }
                                Err(e) => {
                                    warn!("db model error:{}", e);
                                }
                            }
                        }
                    }
                    Err(err) => warn!("grab crawling error:{}", err),
                },
                Err(e) => warn!("join set error:{}", e),
            }
        }
        new_vulns
    }
}
