pub mod _entities;
pub mod error;
pub mod vuln_informations;

pub use error::*;

pub type ModelResult<T, E = ModelError> = std::result::Result<T, E>;
