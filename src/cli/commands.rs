use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Serialize;
use sqlx::{postgres::PgPoolOptions, Row};
use uuid::Uuid;

use crate::core::{
    config as server_config, create_user_sql, derive_credentials, env_u32, generate_invite_code,
    generate_user_secrets, rotate_token_sql, set_enabled_sql,
    subscription::{self, SubscriptionConfig, SubscriptionFormat},
    Credentials, User,
};

pub async fn run(args: &[String]) -> Result<()> {
    match args {
        [] => {
            print_usage();
            Ok(())
        }
        [flag] if is_help(flag) => {
            print_usage();
            Ok(())
        }
        [command, rest @ ..] if command == "bootstrap" => bootstrap(rest).await,
        [command, rest @ ..] if command == "create" => create(rest),
        [command, rest @ ..] if command == "generate-config" => generate_config(rest).await,
        [command, flag] if command == "generate-subscription" && is_help(flag) => {
            print_generate_subscription_usage();
            Ok(())
        }
        [command, uuid, rest @ ..] if command == "generate-subscription" => {
            generate_subscription(uuid, rest).await
        }
        [command, rest @ ..] if command == "generate-subscription-all" => {
            generate_subscription_all(rest).await
        }
        [command, flag] if command == "rotate" && is_help(flag) => {
            print_rotate_usage();
            Ok(())
        }
        [command, uuid, rest @ ..] if command == "rotate" => rotate(uuid, rest),
        [command, uuid] if command == "enable" => set_enabled(uuid, true),
        [command, uuid] if command == "disable" => set_enabled(uuid, false),
        [command, uuid] if command == "inspect" => inspect(uuid).await,
        [command, ..] => {
            print_usage();
            bail!("unknown command: {command}");
        }
    }
}

async fn bootstrap(args: &[String]) -> Result<()> {
    let options = UserInputOptions::parse(args, print_bootstrap_usage)?;
    let pool = database_pool().await?;
    let secrets = generate_user_secrets(&options.password)?;
    let invite = generate_invite_code();
    let mut tx = pool.begin().await.context("begin bootstrap transaction")?;

    sqlx::query("LOCK TABLE users IN EXCLUSIVE MODE")
        .execute(&mut *tx)
        .await
        .context("lock users table")?;

    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&mut *tx)
        .await
        .context("count users")?;
    if user_count != 0 {
        bail!("bootstrap refused: users table is not empty");
    }

    let row = sqlx::query(
        r#"
        INSERT INTO users (name, email, password_hash, token, token_prefix)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING uuid
        "#,
    )
    .bind(&options.name)
    .bind(&options.email)
    .bind(&secrets.password_hash)
    .bind(&secrets.token)
    .bind(&secrets.token_prefix)
    .fetch_one(&mut *tx)
    .await
    .context("insert bootstrap user")?;
    let uuid: Uuid = row.try_get("uuid")?;

    sqlx::query(
        r#"
        INSERT INTO user_invites (user_uuid, code, code_prefix)
        VALUES ($1, $2, $3)
        "#,
    )
    .bind(uuid)
    .bind(&invite.invite_code)
    .bind(&invite.invite_code_prefix)
    .execute(&mut *tx)
    .await
    .context("insert bootstrap invite code")?;

    tx.commit().await.context("commit bootstrap transaction")?;

    println!(
        "{}",
        serde_json::to_string_pretty(&BootstrapOutput {
            uuid,
            name: options.name,
            email: options.email,
            token: secrets.token,
            token_prefix: secrets.token_prefix,
            invite_code: invite.invite_code,
            invite_code_prefix: invite.invite_code_prefix,
        })?
    );

    Ok(())
}

fn create(args: &[String]) -> Result<()> {
    let options = UserInputOptions::parse(args, print_create_usage)?;
    let mut json_output = false;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--name" | "--email" | "--password" => {
                index += 1;
            }
            "--json" => {
                json_output = true;
            }
            "--help" | "-h" => {
                print_create_usage();
                return Ok(());
            }
            option => bail!("unknown option: {option}"),
        }
        index += 1;
    }

    let created = create_user_sql(&options.name, &options.email, &options.password)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&created)?);
    } else {
        println!("-- Plain token, show once and store somewhere safe:");
        println!("-- {}", created.token);
        println!();
        println!("{}", created.sql);
    }

    Ok(())
}

async fn generate_subscription(uuid: &str, args: &[String]) -> Result<()> {
    let uuid = Uuid::parse_str(uuid).context("parse uuid")?;
    let options = SubscriptionOptions::parse(args)?;
    let pool = database_pool().await?;
    let user = load_user(&pool, uuid).await?;

    let output_path = write_subscription(&user, &options)?;
    println!("{}", output_path.display());

    Ok(())
}

async fn generate_subscription_all(args: &[String]) -> Result<()> {
    let options = SubscriptionOptions::parse(args)?;
    let pool = database_pool().await?;
    let users = server_config::load_enabled_users(&pool).await?;

    for user in users {
        let output_path = write_subscription(&user, &options)?;
        println!("{}", output_path.display());
    }

    Ok(())
}

async fn generate_config(args: &[String]) -> Result<()> {
    if !args.is_empty() {
        match args {
            [flag] if flag == "--help" || flag == "-h" => {
                print_generate_config_usage();
                return Ok(());
            }
            [] => {}
            [option, ..] => bail!("unknown option: {option}"),
        }
    }

    let path =
        server_config::render_from_database(&server_config::RenderConfig::from_env()).await?;
    println!("{}", path.display());
    Ok(())
}

fn rotate(uuid: &str, args: &[String]) -> Result<()> {
    let uuid = Uuid::parse_str(uuid).context("parse uuid")?;
    let mut json_output = false;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--json" => {
                json_output = true;
            }
            "--help" | "-h" => {
                print_rotate_usage();
                return Ok(());
            }
            option => bail!("unknown option: {option}"),
        }
        index += 1;
    }

    let rotated = rotate_token_sql(uuid);
    if json_output {
        println!("{}", serde_json::to_string_pretty(&rotated)?);
    } else {
        println!("-- Plain token, show once and store somewhere safe:");
        println!("-- {}", rotated.token);
        println!();
        println!("{}", rotated.sql);
    }

    Ok(())
}

fn set_enabled(uuid: &str, enabled: bool) -> Result<()> {
    let uuid = Uuid::parse_str(uuid).context("parse uuid")?;
    println!("{}", set_enabled_sql(uuid, enabled));
    Ok(())
}

async fn inspect(uuid: &str) -> Result<()> {
    let uuid = Uuid::parse_str(uuid).context("parse uuid")?;
    let pool = database_pool().await?;
    let user = load_user(&pool, uuid).await?;
    let master_secret = master_secret_from_env();
    let credentials = derive_credentials(&user.token, user.uuid, master_secret.as_deref());

    println!(
        "{}",
        serde_json::to_string_pretty(&InspectOutput {
            uuid: user.uuid,
            name: user.name,
            credentials,
        })?
    );

    Ok(())
}

fn write_subscription(user: &User, options: &SubscriptionOptions) -> Result<PathBuf> {
    let config = SubscriptionConfig::from_env()?;
    let master_secret = master_secret_from_env();
    let rendered = subscription::render(options.format, &config, user, master_secret.as_deref())?;
    let output_path =
        options
            .output_dir
            .join(format!("{}.{}", user.uuid, options.format.extension()));

    server_config::atomic_write(&output_path, rendered.as_bytes())?;
    Ok(output_path)
}

async fn database_pool() -> Result<sqlx::PgPool> {
    let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL is required")?;
    PgPoolOptions::new()
        .max_connections(env_u32("DATABASE_MAX_CONNECTIONS", 5))
        .connect(&database_url)
        .await
        .context("connect to PostgreSQL")
}

fn master_secret_from_env() -> Option<String> {
    std::env::var("MASTER_SECRET")
        .ok()
        .filter(|value| !value.is_empty())
}

async fn load_user(pool: &sqlx::PgPool, uuid: Uuid) -> Result<User> {
    let row = sqlx::query(
        r#"
        SELECT uuid, name, token
        FROM users
        WHERE uuid = $1
          AND enabled = TRUE
        "#,
    )
    .bind(uuid)
    .fetch_optional(pool)
    .await
    .context("query user")?
    .with_context(|| format!("enabled user not found: {uuid}"))?;

    Ok(User {
        uuid: row.try_get("uuid")?,
        name: row.try_get("name")?,
        token: row.try_get("token")?,
    })
}

#[derive(Debug, Clone)]
struct SubscriptionOptions {
    format: SubscriptionFormat,
    output_dir: PathBuf,
}

impl SubscriptionOptions {
    fn parse(args: &[String]) -> Result<Self> {
        let mut format = SubscriptionFormat::SingBox;
        let mut output_dir = PathBuf::from(".");

        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--format" => {
                    index += 1;
                    let value = required_arg(args, index, "--format")?;
                    format = SubscriptionFormat::parse(value)
                        .with_context(|| format!("unknown format: {value}"))?;
                }
                "--output-dir" => {
                    index += 1;
                    output_dir = Path::new(required_arg(args, index, "--output-dir")?).into();
                }
                "--help" | "-h" => {
                    print_generate_subscription_usage();
                    std::process::exit(0);
                }
                option => bail!("unknown option: {option}"),
            }
            index += 1;
        }

        Ok(Self { format, output_dir })
    }
}

#[derive(Debug, Serialize)]
struct InspectOutput {
    uuid: Uuid,
    name: String,
    credentials: Credentials,
}

#[derive(Debug)]
struct UserInputOptions {
    name: String,
    email: String,
    password: String,
}

impl UserInputOptions {
    fn parse(args: &[String], print_help: fn()) -> Result<Self> {
        let mut name = None;
        let mut email = None;
        let mut password = None;

        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--name" => {
                    index += 1;
                    name = Some(required_arg(args, index, "--name")?.to_owned());
                }
                "--email" => {
                    index += 1;
                    email = Some(required_arg(args, index, "--email")?.to_owned());
                }
                "--password" => {
                    index += 1;
                    password = Some(required_arg(args, index, "--password")?.to_owned());
                }
                "--json" => {}
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                option => bail!("unknown option: {option}"),
            }
            index += 1;
        }

        let parsed = Self {
            name: name.context("--name is required")?,
            email: email.context("--email is required")?,
            password: password.context("--password is required")?,
        };
        if parsed.name.is_empty() {
            bail!("name cannot be empty");
        }
        if parsed.email.is_empty() {
            bail!("email cannot be empty");
        }
        if parsed.password.is_empty() {
            bail!("password cannot be empty");
        }

        Ok(parsed)
    }
}

#[derive(Debug, Serialize)]
struct BootstrapOutput {
    uuid: Uuid,
    name: String,
    email: String,
    token: String,
    token_prefix: String,
    invite_code: String,
    invite_code_prefix: String,
}

fn required_arg<'a>(args: &'a [String], index: usize, option: &str) -> Result<&'a str> {
    args.get(index)
        .map(String::as_str)
        .filter(|value| !value.starts_with("--"))
        .with_context(|| format!("{option} requires a value"))
}

fn is_help(value: &str) -> bool {
    value == "--help" || value == "-h"
}

fn print_usage() {
    eprintln!(
        "Usage:\n  sing-box-copilot bootstrap --name <name> --email <email> --password <password>\n  sing-box-copilot create --name <name> --email <email> --password <password> [--json]\n  sing-box-copilot generate-config\n  sing-box-copilot generate-subscription <uuid> [--format <format>] [--output-dir <dir>]\n  sing-box-copilot generate-subscription-all [--format <format>] [--output-dir <dir>]\n  sing-box-copilot rotate <uuid> [--json]\n  sing-box-copilot enable <uuid>\n  sing-box-copilot disable <uuid>\n  sing-box-copilot inspect <uuid>"
    );
}

fn print_bootstrap_usage() {
    eprintln!(
        "Usage:\n  sing-box-copilot bootstrap --name <name> --email <email> --password <password>"
    );
}

fn print_create_usage() {
    eprintln!(
        "Usage:\n  sing-box-copilot create --name <name> --email <email> --password <password> [--json]"
    );
}

fn print_generate_config_usage() {
    eprintln!("Usage:\n  sing-box-copilot generate-config");
}

fn print_generate_subscription_usage() {
    eprintln!(
        "Usage:\n  sing-box-copilot generate-subscription <uuid> [--format <format>] [--output-dir <dir>]\n  sing-box-copilot generate-subscription-all [--format <format>] [--output-dir <dir>]\n\nFormats: sing-box, clash, shadowrocket\nDefault format: sing-box"
    );
}

fn print_rotate_usage() {
    eprintln!("Usage:\n  sing-box-copilot rotate <uuid> [--json]");
}
