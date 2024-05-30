pub use sea_orm_migration::prelude::*;

mod m20240417_015641_create_vuln_information;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(
            m20240417_015641_create_vuln_information::Migration,
        )]
    }
}
