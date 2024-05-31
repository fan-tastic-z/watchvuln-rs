pub use sea_orm_migration::prelude::*;

mod m20240417_015641_create_vuln_information;
mod m20240531_131002_alter_vuln_add_is_valuable_field;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20240417_015641_create_vuln_information::Migration),
            Box::new(m20240531_131002_alter_vuln_add_is_valuable_field::Migration),
        ]
    }
}
