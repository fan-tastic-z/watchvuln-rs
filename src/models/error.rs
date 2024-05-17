#[derive(thiserror::Error, Debug)]
pub enum ModelError {
    #[error("Entity {} already exists", key)]
    EntityAlreadyExists { key: String },

    #[error("Entity not found")]
    EntityNotFound,

    #[error("Entity update not found by key: {}", key)]
    EntityUpdateNotFound { key: String },

    #[error(transparent)]
    DbErr(#[from] sea_orm::DbErr),

    #[error(transparent)]
    Any(#[from] Box<dyn std::error::Error + Send + Sync>),
}
