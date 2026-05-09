use std::{
    env, fs,
    path::{Path, PathBuf},
    process,
};

use anyhow::{Context, Result};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, Row};
use tracing::info;
use uuid::Uuid;

use crate::core::{derive_credentials, env_u32, User};

#[derive(Debug, Clone)]
pub struct RenderConfig {
    pub config_path: PathBuf,
    pub master_secret: Option<String>,
}

impl RenderConfig {
    pub fn from_env() -> Self {
        Self {
            config_path: config_path_from_env(),
            master_secret: env::var("MASTER_SECRET")
                .ok()
                .filter(|value| !value.is_empty()),
        }
    }
}

pub async fn load_enabled_users(pool: &sqlx::PgPool) -> Result<Vec<User>> {
    let rows = sqlx::query(
        r#"
        SELECT uuid, name, token
        FROM users
        WHERE enabled = TRUE
        ORDER BY created_at, email
        "#,
    )
    .fetch_all(pool)
    .await
    .context("query enabled users")?;

    rows.into_iter()
        .map(|row| {
            Ok(User {
                uuid: row.try_get::<Uuid, _>("uuid")?,
                name: row.try_get("name")?,
                token: row.try_get("token")?,
            })
        })
        .collect()
}

pub async fn render_from_database(config: &RenderConfig) -> Result<PathBuf> {
    let database_url = env::var("DATABASE_URL").context("DATABASE_URL is required")?;
    let pool = PgPoolOptions::new()
        .max_connections(env_u32("DATABASE_MAX_CONNECTIONS", 5))
        .connect(&database_url)
        .await
        .context("connect to PostgreSQL")?;

    let users = load_enabled_users(&pool).await?;
    info!(count = users.len(), "loaded enabled users");

    let base = fs::read_to_string(&config.config_path)
        .with_context(|| format!("read {}", config.config_path.display()))?;
    let mut document: Value = serde_json::from_str(&base).context("parse sing-box config JSON")?;
    generate_config(&mut document, &users, config.master_secret.as_deref())?;

    let rendered = serde_json::to_string_pretty(&document).context("serialize sing-box config")?;
    atomic_write(&config.config_path, rendered.as_bytes())?;
    info!(path = %config.config_path.display(), "wrote rendered sing-box config");

    Ok(config.config_path.clone())
}

pub fn generate_config(
    document: &mut Value,
    users: &[User],
    master_secret: Option<&str>,
) -> Result<()> {
    let inbounds = document
        .get_mut("inbounds")
        .and_then(Value::as_array_mut)
        .context("inbounds must be an array")?;

    for inbound in inbounds {
        let inbound_type = inbound
            .get("type")
            .and_then(Value::as_str)
            .context("inbound.type must be a string")?
            .to_owned();
        render_inbound_users(inbound, &inbound_type, users, master_secret)?;
    }

    Ok(())
}

fn render_inbound_users(
    inbound: &mut Value,
    inbound_type: &str,
    users: &[User],
    master_secret: Option<&str>,
) -> Result<()> {
    match inbound_type {
        "shadowtls" => set_users(
            inbound,
            users
                .iter()
                .map(|user| {
                    let credentials = derive_credentials(&user.token, user.uuid, master_secret);
                    json!({
                        "name": user.name,
                        "password": credentials.shadowtls
                    })
                })
                .collect(),
        ),
        "shadowsocks" => set_users(
            inbound,
            users
                .iter()
                .map(|user| {
                    let credentials = derive_credentials(&user.token, user.uuid, master_secret);
                    json!({
                        "name": user.name,
                        "password": credentials.shadowsocks
                    })
                })
                .collect(),
        ),
        "vmess" => set_users(
            inbound,
            users
                .iter()
                .map(|user| {
                    json!({
                        "name": user.name,
                        "uuid": user.uuid,
                        "alterId": 0
                    })
                })
                .collect(),
        ),
        "trojan" => set_users(
            inbound,
            users
                .iter()
                .map(|user| {
                    let credentials = derive_credentials(&user.token, user.uuid, master_secret);
                    json!({
                        "name": user.name,
                        "password": credentials.trojan
                    })
                })
                .collect(),
        ),
        "naive" => set_users(
            inbound,
            users
                .iter()
                .map(|user| {
                    let credentials = derive_credentials(&user.token, user.uuid, master_secret);
                    json!({
                        "username": user.name,
                        "password": credentials.naive
                    })
                })
                .collect(),
        ),
        "tuic" => set_users(
            inbound,
            users
                .iter()
                .map(|user| {
                    let credentials = derive_credentials(&user.token, user.uuid, master_secret);
                    json!({
                        "uuid": user.uuid,
                        "password": credentials.tuic
                    })
                })
                .collect(),
        ),
        "anytls" => set_users(
            inbound,
            users
                .iter()
                .map(|user| {
                    let credentials = derive_credentials(&user.token, user.uuid, master_secret);
                    json!({
                        "name": user.name,
                        "password": credentials.anytls
                    })
                })
                .collect(),
        ),
        "hysteria2" => set_users(
            inbound,
            users
                .iter()
                .map(|user| {
                    let credentials = derive_credentials(&user.token, user.uuid, master_secret);
                    json!({
                        "name": user.name,
                        "password": credentials.hysteria2
                    })
                })
                .collect(),
        ),
        other => {
            info!(
                inbound_type = other,
                "leaving unsupported inbound type unchanged"
            );
            Ok(())
        }
    }
}

fn set_users(inbound: &mut Value, users: Vec<Value>) -> Result<()> {
    inbound["users"] = Value::Array(users);
    Ok(())
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("output path must have parent")?;
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;

    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("output path must have a valid file name")?;
    let tmp_path = path.with_file_name(format!(".{file_name}.{}.tmp", process::id()));
    fs::write(&tmp_path, bytes).with_context(|| format!("write {}", tmp_path.display()))?;
    fs::rename(&tmp_path, path)
        .with_context(|| format!("rename {} to {}", tmp_path.display(), path.display()))?;
    Ok(())
}

pub fn config_path_from_env() -> PathBuf {
    env::var("SING_BOX_CONFIG_PATH")
        .map(expand_home)
        .unwrap_or_else(|_| expand_home("~/.config/sing-box/config.json"))
}

fn expand_home(value: impl AsRef<str>) -> PathBuf {
    let value = value.as_ref();
    if let Some(rest) = value.strip_prefix("~/") {
        if let Ok(home) = env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(value)
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn generate_config_sets_users_on_inbounds() {
        let mut document: Value = serde_json::json!({
            "inbounds": [
                {
                    "tag": "inbounds-shadowtls",
                    "type": "shadowtls",
                    "users": [
                        {
                            "password": "server-password"
                        }
                    ]
                },
                {
                    "tag": "inbounds-shadowsocks",
                    "type": "shadowsocks",
                    "method": "2022-blake3-aes-128-gcm",
                    "password": "server-password"
                },
                {
                    "tag": "inbounds-vmess",
                    "type": "vmess",
                    "users": [
                        {
                            "uuid": "server-uuid",
                            "alterId": 0
                        }
                    ]
                },
                {
                    "tag": "inbounds-trojan",
                    "type": "trojan"
                }
            ]
        });
        let users = vec![User {
            uuid: Uuid::parse_str("5946ceeb-0363-42d5-8d23-ceae21da428f").unwrap(),
            name: "chao".to_owned(),
            token: "token".to_owned(),
        }];

        generate_config(&mut document, &users, None).unwrap();
        let inbounds = document["inbounds"].as_array().unwrap();

        assert_eq!(inbounds[0]["users"][0]["name"], "chao");
        assert!(inbounds[0]["users"][0]["password"].as_str().is_some());
        assert_eq!(inbounds[1]["users"][0]["name"], "chao");
        assert!(inbounds[1]["users"][0]["password"].as_str().is_some());
        assert_eq!(
            inbounds[2]["users"][0]["uuid"],
            "5946ceeb-0363-42d5-8d23-ceae21da428f"
        );
        assert_eq!(inbounds[3]["users"][0]["name"], "chao");
        assert!(inbounds[3]["users"][0]["password"].as_str().is_some());
    }
}
