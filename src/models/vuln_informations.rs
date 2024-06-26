use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait,
    QueryFilter, TransactionTrait,
};
use snafu::{ensure, OptionExt, ResultExt};
use tracing::info;

use crate::{
    error::{DbAlreadyExistsSnafu, DbErrSnafu, DbNotFoundErrSnafu, Result},
    grab::VulnInfo,
};

use super::_entities::vuln_informations;

const REASON_NEW_CREATED: &str = "漏洞创建";
const REASON_TAG_UPDATED: &str = "标签更新";
const REASON_SEVERITY_UPDATE: &str = "等级更新";

impl super::_entities::vuln_informations::Model {
    pub async fn find_by_id(db: &DatabaseConnection, key: &str) -> Result<Self> {
        let vuln = vuln_informations::Entity::find()
            .filter(vuln_informations::Column::Key.eq(key))
            .one(db)
            .await
            .context(DbErrSnafu)?;
        let res = vuln.with_context(|| DbNotFoundErrSnafu {
            table: "vuln_informations".to_string(),
            filter: key.to_string(),
        })?;
        Ok(res)
    }

    pub async fn query_count(db: &DatabaseConnection) -> Result<u64> {
        let count = vuln_informations::Entity::find()
            .count(db)
            .await
            .context(DbErrSnafu)?;
        Ok(count)
    }

    pub async fn creat_or_update(db: &DatabaseConnection, mut vuln: VulnInfo) -> Result<Self> {
        let txn = db.begin().await.context(DbErrSnafu)?;
        let v = vuln_informations::Entity::find()
            .filter(vuln_informations::Column::Key.eq(vuln.unique_key.clone()))
            .one(&txn)
            .await
            .context(DbErrSnafu)?;
        if let Some(v) = v {
            let mut vuln_model: vuln_informations::ActiveModel = v.into();
            let mut as_new_vuln = false;
            // severtiy update
            let severtiy = vuln_model.severtiy.as_ref().to_owned();
            if severtiy != vuln.severity.to_string() {
                info!(
                    "{} from {} change severity from {} to {}",
                    vuln_model.title.as_ref(),
                    vuln_model.from.as_ref(),
                    vuln_model.severtiy.as_ref(),
                    vuln.severity.to_string()
                );
                let reason = format!(
                    "{}: {} => {}",
                    REASON_SEVERITY_UPDATE,
                    vuln_model.severtiy.as_ref(),
                    vuln.severity
                );
                vuln.reasons.push(reason);

                as_new_vuln = true
            }

            // tag update
            if let Some(tags) = vuln_model.tags.as_ref() {
                let new_tags = vuln
                    .tags
                    .iter()
                    .filter(|&x| !tags.contains(x))
                    .collect::<Vec<_>>();
                if !new_tags.is_empty() {
                    info!(
                        "{} from {} add new tag {:?}",
                        vuln.title, vuln.from, new_tags
                    );
                    let reason = format!(
                        "{}: {:?} => {:?}",
                        REASON_TAG_UPDATED,
                        vuln_model.tags.as_ref(),
                        vuln.tags
                    );
                    vuln.reasons.push(reason);
                    as_new_vuln = true
                }
            }

            ensure!(
                as_new_vuln,
                DbAlreadyExistsSnafu {
                    table: "vuln_informations".to_string(),
                    filter: vuln.unique_key.clone()
                }
            );

            vuln_model.title = ActiveValue::set(vuln.title);
            vuln_model.description = ActiveValue::set(vuln.description);
            vuln_model.severtiy = ActiveValue::set(vuln.severity.to_string());
            vuln_model.disclosure = ActiveValue::set(vuln.disclosure);
            vuln_model.solutions = ActiveValue::set(vuln.solutions);
            vuln_model.references = ActiveValue::set(Some(vuln.references));
            vuln_model.tags = ActiveValue::set(Some(vuln.tags));
            vuln_model.from = ActiveValue::set(vuln.from);
            vuln_model.reasons = ActiveValue::set(Some(vuln.reasons));
            vuln_model.is_valuable = ActiveValue::set(vuln.is_valuable);
            // if tags or severtiy update should set pushed false, repush
            vuln_model.pushed = ActiveValue::set(false);
            let m = vuln_model.update(&txn).await.context(DbErrSnafu)?;
            txn.commit().await.context(DbErrSnafu)?;
            return Ok(m);
        }
        vuln.reasons.push(REASON_NEW_CREATED.to_owned());
        let v = vuln_informations::ActiveModel {
            key: ActiveValue::set(vuln.unique_key),
            title: ActiveValue::set(vuln.title),
            description: ActiveValue::set(vuln.description),
            severtiy: ActiveValue::set(vuln.severity.to_string()),
            cve: ActiveValue::set(vuln.cve),
            disclosure: ActiveValue::set(vuln.disclosure),
            solutions: ActiveValue::set(vuln.solutions),
            references: ActiveValue::set(Some(vuln.references)),
            tags: ActiveValue::set(Some(vuln.tags)),
            from: ActiveValue::set(vuln.from),
            pushed: ActiveValue::set(false),
            reasons: ActiveValue::set(Some(vuln.reasons)),
            is_valuable: ActiveValue::set(vuln.is_valuable),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .context(DbErrSnafu)?;
        txn.commit().await.context(DbErrSnafu)?;
        Ok(v)
    }

    pub async fn update_github_search_by_key(
        db: &DatabaseConnection,
        key: &str,
        links: Vec<String>,
    ) -> Result<()> {
        let txn = db.begin().await.context(DbErrSnafu)?;
        let v = vuln_informations::Entity::find()
            .filter(vuln_informations::Column::Key.eq(key))
            .one(&txn)
            .await
            .context(DbErrSnafu)?;
        let res = v.with_context(|| DbNotFoundErrSnafu {
            table: "vuln_informations".to_string(),
            filter: key.to_string(),
        })?;
        let mut v: vuln_informations::ActiveModel = res.into();
        v.github_search = ActiveValue::set(Some(links));
        v.update(&txn).await.context(DbErrSnafu)?;
        txn.commit().await.context(DbErrSnafu)?;
        Ok(())
    }

    pub async fn update_pushed_by_key(db: &DatabaseConnection, key: String) -> Result<()> {
        let txn = db.begin().await.context(DbErrSnafu)?;
        let v = vuln_informations::Entity::find()
            .filter(vuln_informations::Column::Key.eq(key.clone()))
            .one(&txn)
            .await
            .context(DbErrSnafu)?;

        let res = v.with_context(|| DbNotFoundErrSnafu {
            table: "vuln_informations".to_string(),
            filter: key,
        })?;
        let mut v: vuln_informations::ActiveModel = res.into();
        v.pushed = ActiveValue::set(true);
        v.update(&txn).await.context(DbErrSnafu)?;
        txn.commit().await.context(DbErrSnafu)?;
        Ok(())
    }

    pub async fn create(db: &DatabaseConnection, vuln: VulnInfo) -> Result<Self> {
        let txn = db.begin().await.context(DbErrSnafu)?;
        let res = vuln_informations::Entity::find()
            .filter(vuln_informations::Column::Key.eq(vuln.unique_key.clone()))
            .one(&txn)
            .await
            .context(DbErrSnafu)?;
        ensure!(
            res.is_some(),
            DbAlreadyExistsSnafu {
                table: "vuln_informations".to_string(),
                filter: vuln.unique_key.clone(),
            }
        );
        let v = vuln_informations::ActiveModel {
            key: ActiveValue::set(vuln.unique_key),
            title: ActiveValue::set(vuln.title),
            description: ActiveValue::set(vuln.description),
            severtiy: ActiveValue::set(vuln.severity.to_string()),
            cve: ActiveValue::set(vuln.cve),
            disclosure: ActiveValue::set(vuln.disclosure),
            solutions: ActiveValue::set(vuln.solutions),
            references: ActiveValue::set(Some(vuln.references)),
            tags: ActiveValue::set(Some(vuln.tags)),
            from: ActiveValue::set(vuln.from),
            is_valuable: ActiveValue::set(vuln.is_valuable),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .context(DbErrSnafu)?;
        txn.commit().await.context(DbErrSnafu)?;
        Ok(v)
    }
}
