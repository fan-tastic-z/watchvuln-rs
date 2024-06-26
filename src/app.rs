use lazy_static::lazy_static;
use migration::MigratorTrait;
use sea_orm::DatabaseConnection;
use snafu::ResultExt;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{runtime::Runtime, task::JoinSet, time};
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::{error, info, warn};

use crate::{
    config::Config,
    db,
    environment::Environment,
    error::{CronSchedulerErrSnafu, DbErrSnafu, Result},
    grab::{self, Grab, VulnInfo},
    models::_entities::vuln_informations::{self, Model},
    push::{
        self,
        msg_template::{reader_vulninfo, render_init},
        BotManager,
    },
    search::search_github_poc,
};

lazy_static! {
    static ref VERSION: &'static str = env!("CARGO_PKG_VERSION");
}

const PAGE_LIMIT: i32 = 1;
const INIT_PAGE_LIMIT: i32 = 2;

#[derive(Clone)]
pub struct WatchVulnApp {
    pub app_context: Arc<AppContext>,
    pub grabs: Arc<HashMap<String, Arc<Box<dyn Grab>>>>,
}

impl WatchVulnApp {
    pub fn new(app_context: Arc<AppContext>) -> Self {
        let grab_manager = grab::init();
        let map: HashMap<String, Arc<Box<dyn Grab>>> = grab_manager
            .map
            .into_iter()
            .map(|(k, v)| (k, Arc::new(v)))
            .collect();
        let grabs = Arc::new(map);
        WatchVulnApp { app_context, grabs }
    }

    fn crawling_job(&self) -> Result<Job> {
        let schedule = self.app_context.config.task.cron_config.as_str();
        let self_arc = Arc::new(self.clone());
        let job = Job::new_async_tz(
            schedule,
            chrono_tz::Asia::Shanghai,
            move |uuid, mut lock| {
                let self_clone = self_arc.clone();
                Box::pin(async move {
                    let res: Vec<VulnInfo> = self_clone
                        .crawling_task(false)
                        .await
                        .into_iter()
                        .map(|x| x.into())
                        .collect();
                    info!("crawling over all count is: {}", res.len());
                    let rt1 = Runtime::new().unwrap();
                    rt1.block_on(async move {
                        self_clone.push(res).await;
                    });
                    let next_tick = lock.next_tick_for_job(uuid).await;
                    if let Ok(Some(tick)) = next_tick {
                        info!(
                            "Next time for job is: {}",
                            tick.with_timezone(&chrono_tz::Asia::Shanghai)
                        );
                    }
                })
            },
        )
        .context(CronSchedulerErrSnafu)?;
        Ok(job)
    }

    pub async fn run(&self) -> Result<()> {
        let self_arc = Arc::new(self.clone());

        // init data
        self_arc.crawling_task(true).await;
        let local_count = vuln_informations::Model::query_count(&self.app_context.db).await?;
        info!("init finished, local database has {} vulns", local_count);
        self.push_init_msg(local_count).await?;

        let sched = JobScheduler::new().await.context(CronSchedulerErrSnafu)?;
        let job = self.crawling_job()?;

        sched.add(job).await.context(CronSchedulerErrSnafu)?;
        sched.start().await.context(CronSchedulerErrSnafu)?;
        loop {
            time::sleep(Duration::from_secs(60)).await;
        }
    }

    async fn crawling_task(&self, is_init: bool) -> Vec<Model> {
        tracing::info!("{:?}", self.app_context.config);
        let mut set = JoinSet::new();
        for v in self.grabs.as_ref().values() {
            let grab = v.to_owned();
            if is_init {
                // set.spawn(async move { grab.get_update(INIT_PAGE_LIMIT).await });
                set.spawn(async move {
                    grab.get_update(INIT_PAGE_LIMIT)
                        .await
                        .expect("crawling error")
                });
            } else {
                set.spawn(
                    async move { grab.get_update(PAGE_LIMIT).await.expect("crawling error") },
                );
            }
        }
        let mut new_vulns = Vec::new();
        while let Some(set_res) = set.join_next().await {
            match set_res {
                Ok(grabs_res) => {
                    for v in grabs_res {
                        let create_res =
                            vuln_informations::Model::creat_or_update(&self.app_context.db, v)
                                .await;
                        match create_res {
                            Ok(m) => {
                                info!("found new vuln:{}", m.key);
                                new_vulns.push(m)
                            }
                            Err(e) => {
                                warn!("db model error:{:?}", e);
                            }
                        }
                    }
                }
                Err(e) => warn!("join set error:{:?}", e),
            }
        }
        new_vulns
    }

    async fn push(&self, vulns: Vec<VulnInfo>) {
        for mut vuln in vulns.into_iter() {
            if vuln.is_valuable {
                if vuln.pushed {
                    info!("{} has been pushed, skipped", vuln.unique_key);
                    continue;
                }

                let key = vuln.unique_key.clone();
                let title = vuln.title.clone();
                if !vuln.cve.is_empty() && self.app_context.config.github_search {
                    let links = search_github_poc(&vuln.cve).await;
                    info!("{} found {} links from github", &vuln.cve, links.len());
                    if !links.is_empty() {
                        if let Err(err) = vuln_informations::Model::update_github_search_by_key(
                            &self.app_context.db,
                            &key,
                            links.clone(),
                        )
                        .await
                        {
                            warn!("update vuln {} github_search error: {:?}", &vuln.cve, err);
                        }
                        vuln.github_search = links;
                    }
                }
                let msg = match reader_vulninfo(vuln) {
                    Ok(msg) => msg,
                    Err(err) => {
                        warn!("reader vulninfo {} error {:?}", key, err);
                        continue;
                    }
                };
                let is_push = self.push_all(title, msg.clone()).await;
                if is_push {
                    info!("all bot push success update db will pushed true");
                    if let Err(err) =
                        vuln_informations::Model::update_pushed_by_key(&self.app_context.db, key)
                            .await
                    {
                        warn!("update vuln {} pushed error: {:?}", msg, err);
                    }
                }
            }
        }
    }

    async fn push_init_msg(&self, local_count: u64) -> Result<()> {
        let grabs = self.get_all_grabs();
        let init_msg = render_init(
            VERSION.to_string(),
            local_count,
            self.app_context.config.task.cron_config.clone(),
            grabs,
        )?;

        self.push_all("WatchVuln-rs init success".to_string(), init_msg)
            .await;
        Ok(())
    }

    fn get_all_grabs(&self) -> Vec<String> {
        let grabs = self.grabs.clone();
        let mut res = Vec::new();
        for v in grabs.values() {
            res.push(v.get_name())
        }
        res
    }

    pub async fn push_all(&self, title: String, msg: String) -> bool {
        let mut set = JoinSet::new();
        for bot in &self.app_context.bot_manager.bots {
            let bot_clone = bot.clone();
            let message = msg.clone();
            let title = title.clone();
            set.spawn(async move {
                if let Err(e) = bot_clone.push_markdown(title, message).await {
                    error!("push to bot error: {:?}", e);
                    warn!("push to bot error: {:?}", e);
                    return Err(format!("push to bot error:{}", e));
                }
                Ok(())
            });
        }
        let mut is_push = true;
        while let Some(set_res) = set.join_next().await {
            if set_res.is_err() {
                is_push = false;
            }
        }
        is_push
    }

    pub async fn run_migration(&self) -> Result<()> {
        migration::Migrator::up(&self.app_context.db, None)
            .await
            .context(DbErrSnafu)?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct AppContext {
    pub environment: Environment,
    pub config: Config,
    pub db: DatabaseConnection,
    pub bot_manager: BotManager,
}

pub async fn create_context(environment: &Environment) -> Result<AppContext> {
    let config = environment.load()?;
    let db = db::connect(&config.database).await.context(DbErrSnafu)?;
    let bot_manager = push::init(config.clone());
    Ok(AppContext {
        environment: environment.clone(),
        config,
        db,
        bot_manager,
    })
}
