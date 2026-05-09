use anyhow::{Context, Result};
use sqlx::{postgres::PgPoolOptions, PgPool};

use crate::core::{env_u32, subscription::SubscriptionConfig, ServerBindConfig};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub bind_config: ServerBindConfig,
    pub subscription_config: SubscriptionConfig,
    pub master_secret: Option<String>,
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
        })
    }
}
