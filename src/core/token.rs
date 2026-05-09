use anyhow::{bail, Context, Result};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose, Engine};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use uuid::Uuid;

pub const TOKEN_PREFIX: &str = "verzea_";

#[derive(Debug, Clone, Serialize)]
pub struct CreatedUserSql {
    pub token: String,
    pub token_prefix: String,
    pub sql: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeneratedToken {
    pub token: String,
    pub token_prefix: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeneratedTokenSql {
    pub token: String,
    pub token_prefix: String,
    pub sql: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserSecrets {
    pub token: String,
    pub token_prefix: String,
    pub password_hash: String,
}

pub fn create_user_sql(name: &str, email: &str, password: &str) -> Result<CreatedUserSql> {
    if name.is_empty() {
        bail!("name cannot be empty");
    }
    if email.is_empty() {
        bail!("email cannot be empty");
    }
    if password.is_empty() {
        bail!("password cannot be empty");
    }

    let secrets = generate_user_secrets(password)?;
    let sql = format!(
        "INSERT INTO users (\n  name,\n  email,\n  password_hash,\n  token,\n  token_prefix\n) VALUES (\n  '{}',\n  '{}',\n  '{}',\n  '{}',\n  '{}'\n) RETURNING uuid;",
        sql_quote(name),
        sql_quote(email),
        sql_quote(&secrets.password_hash),
        sql_quote(&secrets.token),
        sql_quote(&secrets.token_prefix),
    );

    Ok(CreatedUserSql {
        token: secrets.token,
        token_prefix: secrets.token_prefix,
        sql,
    })
}

pub fn generate_user_secrets(password: &str) -> Result<UserSecrets> {
    if password.is_empty() {
        bail!("password cannot be empty");
    }

    let generated_token = generate_token();
    let password_hash = hash_password(password).context("hash password")?;

    Ok(UserSecrets {
        token: generated_token.token,
        token_prefix: generated_token.token_prefix,
        password_hash,
    })
}

pub fn generate_token() -> GeneratedToken {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let token = format!(
        "{TOKEN_PREFIX}{}",
        general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    );
    let token_prefix = token.chars().take(16).collect();

    GeneratedToken {
        token,
        token_prefix,
    }
}

pub fn rotate_token_sql(uuid: Uuid) -> GeneratedTokenSql {
    let generated_token = generate_token();
    let sql = format!(
        "UPDATE users\nSET token = '{}',\n    token_prefix = '{}',\n    token_rotated_at = now()\nWHERE uuid = '{}'\nRETURNING uuid;",
        sql_quote(&generated_token.token),
        sql_quote(&generated_token.token_prefix),
        uuid,
    );

    GeneratedTokenSql {
        token: generated_token.token,
        token_prefix: generated_token.token_prefix,
        sql,
    }
}

pub fn set_enabled_sql(uuid: Uuid, enabled: bool) -> String {
    format!(
        "UPDATE users\nSET enabled = {}\nWHERE uuid = '{}'\nRETURNING uuid;",
        if enabled { "TRUE" } else { "FALSE" },
        uuid,
    )
}

pub fn hash_password(value: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(value.as_bytes(), &salt)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?
        .to_string())
}

pub fn verify_password(password: &str, password_hash: &str) -> Result<bool> {
    let parsed_hash =
        PasswordHash::new(password_hash).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

pub fn sql_quote(value: &str) -> String {
    value.replace('\'', "''")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_argon2_password_hash() {
        let password_hash = hash_password("correct horse battery staple").unwrap();

        assert!(verify_password("correct horse battery staple", &password_hash).unwrap());
        assert!(!verify_password("wrong password", &password_hash).unwrap());
    }

    #[test]
    fn generated_tokens_use_fixed_prefix() {
        let token = generate_token();

        assert!(token.token.starts_with(TOKEN_PREFIX));
    }
}
