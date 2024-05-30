use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let table = table_auto(VulnInformations::Table)
            .col(pk_auto(VulnInformations::Id))
            .col(string_uniq(VulnInformations::Key))
            .col(string(VulnInformations::Title))
            .col(string(VulnInformations::Description))
            .col(string(VulnInformations::Severtiy))
            .col(string(VulnInformations::CVE))
            .col(string(VulnInformations::Disclosure))
            .col(string(VulnInformations::Solutions))
            .col(array_null(
                VulnInformations::References,
                ColumnType::string(Some(512)),
            ))
            .col(array_null(
                VulnInformations::Tags,
                ColumnType::string(Some(512)),
            ))
            .col(array_null(
                VulnInformations::GithubSearch,
                ColumnType::string(Some(512)),
            ))
            .col(array_null(
                VulnInformations::Reasons,
                ColumnType::string(Some(512)),
            ))
            .col(string(VulnInformations::From))
            .col(boolean(VulnInformations::Pushed))
            .to_owned();

        manager.create_table(table).await?;
        manager
            .create_index(
                Index::create()
                    .name("idx-vuln-from")
                    .table(VulnInformations::Table)
                    .col(VulnInformations::From)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx-vuln-pushed")
                    .table(VulnInformations::Table)
                    .col(VulnInformations::Pushed)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(VulnInformations::Table).to_owned())
            .await
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(DeriveIden)]
enum VulnInformations {
    Table,
    Id,
    Key,
    Title,
    Description,
    Severtiy,
    CVE,
    Disclosure,
    Solutions,
    References,
    Tags,
    GithubSearch,
    Reasons,
    From,
    Pushed,
}
