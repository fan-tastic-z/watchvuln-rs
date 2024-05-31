use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                sea_query::Table::alter()
                    .table(VulnInformations::Table)
                    .add_column(boolean(VulnInformations::IsValuable).default(false))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                sea_query::Table::alter()
                    .table(VulnInformations::Table)
                    .drop_column(VulnInformations::IsValuable)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum VulnInformations {
    Table,
    IsValuable,
}
