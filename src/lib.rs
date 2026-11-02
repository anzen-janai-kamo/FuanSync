pub mod auth;
pub mod binary;
pub mod cli;
pub mod install;
pub mod protocol;
pub mod record;

pub type Result<T> = std::result::Result<T, &'static str>;
