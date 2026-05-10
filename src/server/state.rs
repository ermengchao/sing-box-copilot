use anyhow::{Context, Result};
use std::collections::HashSet;

use sqlx::{postgres::PgPoolOptions, PgPool};

use crate::core::{env_u32, subscription::SubscriptionConfig, ServerBindConfig};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub bind_config: ServerBindConfig,
    pub subscription_config: SubscriptionConfig,
    pub master_secret: Option<String>,
    pub email_allow_list: HashSet<String>,
}

impl AppState {
    pub async fn from_env() -> Result<Self> {
        let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL is required")?;
        let pool = PgPoolOptions::new()
            .max_connections(env_u32("DATABASE_MAX_CONNECTIONS", 5))
            .connect(&database_url)
            .await
            .context("connect to PostgreSQL")?;

        Ok(Self {
            pool,
            bind_config: ServerBindConfig::from_env(),
            subscription_config: SubscriptionConfig::from_env()?,
            master_secret: std::env::var("MASTER_SECRET")
                .ok()
                .filter(|value| !value.is_empty()),
            email_allow_list: email_allow_list_from_env(),
        })
    }
}

fn email_allow_list_from_env() -> HashSet<String> {
    std::env::var("EMAIL_ALLOW_LIST")
        .ok()
        .unwrap_or_default()
        .split([',', '\n'])
        .map(normalize_email)
        .filter(|value| !value.is_empty())
        .collect()
}

pub fn normalize_email(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}
