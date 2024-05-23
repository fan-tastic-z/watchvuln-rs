use sea_orm::DatabaseConnection;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{task::JoinSet, time};
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::{debug, info, warn};

use crate::{
    config::Config,
    db,
    environment::Environment,
    error::Result,
    grab::{self, Grab, Severity},
    models::_entities::vuln_informations::{self, Model},
    push::{msg_template::reader_vulninfo, telegram::Telegram},
};

const PAGE_LIMIT: i32 = 1;

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
        let schedule = self.app_context.config.task.cron_config.as_str();
        let job = Job::new_async(schedule, move |_uuid, _lock| {
            let self_clone = self_arc.clone();
            Box::pin(async move {
                let res = self_clone.crawling_task().await;
                debug!("crawling over, result is : {:#?}", res);
                self_clone.push(res).await;
            })
        })?;

        sched.add(job).await?;
        sched.start().await?;
        loop {
            time::sleep(Duration::from_secs(60)).await;
        }
    }

    async fn crawling_task(&self) -> Vec<Model> {
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

    async fn push(&self, vulns: Vec<Model>) {
        for vuln in vulns.into_iter() {
            if vuln.severtiy == Severity::Critical.to_string()
                || vuln.severtiy == Severity::Critical.to_string()
            {
                if vuln.pushed {
                    info!("{} has been pushed, skipped", vuln.key);
                    continue;
                }
                let key = vuln.key.clone();
                let msg = match reader_vulninfo(vuln.into()) {
                    Ok(msg) => msg,
                    Err(err) => {
                        warn!("reader vulninfo {} error {}", key, err);
                        continue;
                    }
                };
                if let Err(err) = self.app_context.tg_bot.push_markdown(msg.clone()).await {
                    warn!("push vuln {} msg {} error: {}", key, msg, err);
                };
                if let Err(err) =
                    vuln_informations::Model::update_pushed_by_key(&self.app_context.db, key).await
                {
                    warn!("update vuln {} pushed error: {}", msg, err);
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct AppContext {
    pub environment: Environment,
    pub config: Config,
    pub db: DatabaseConnection,
    pub tg_bot: Telegram,
}

pub async fn create_context(environment: &Environment) -> Result<AppContext> {
    let config = environment.load()?;
    let db = db::connect(&config.database).await?;
    let tg_bot = Telegram::new(config.tg_bot.token.clone(), config.tg_bot.chat_id);
    Ok(AppContext {
        environment: environment.clone(),
        config,
        db,
        tg_bot,
    })
}
