use std::env;

use uuid::Uuid;

pub mod config;
pub mod credentials;
pub mod subscription;
pub mod token;

pub use credentials::{derive_credentials, Credentials};
pub use token::{
    create_user_sql, generate_token, generate_user_secrets, hash_password, rotate_token_sql,
    set_enabled_sql, verify_password, CreatedUserSql, GeneratedToken, GeneratedTokenSql,
    UserSecrets, TOKEN_PREFIX,
};

#[derive(Debug, Clone)]
pub struct ServerBindConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct User {
    pub uuid: Uuid,
    pub name: String,
    pub token: String,
}

impl ServerBindConfig {
    pub fn from_env() -> Self {
        Self {
            host: env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: env_u16("PORT", 2002),
        }
    }
}

pub fn normalize_path(value: &str) -> String {
    if value.starts_with('/') {
        value.to_owned()
    } else {
        format!("/{value}")
    }
}

pub fn env_u16(name: &str, default: u16) -> u16 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

pub fn env_u32(name: &str, default: u32) -> u32 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
