use async_graphql::{Context, EmptySubscription, Object, Result, Schema, SimpleObject};
use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    core::{
        generate_invite_code, generate_user_secrets,
        subscription::{self, SubscriptionFormat},
        verify_password, User,
    },
    server::state::{normalize_email, AppState},
};

pub type AppSchema = Schema<QueryRoot, MutationRoot, EmptySubscription>;

#[derive(Default)]
pub struct QueryRoot;

#[Object]
impl QueryRoot {
    async fn health(&self) -> &'static str {
        "ok"
    }

    async fn subscription(
        &self,
        ctx: &Context<'_>,
        token: String,
        format: Option<String>,
    ) -> Result<SubscriptionPayload> {
        let state = ctx.data::<AppState>()?;
        let user = load_enabled_user_by_token(state, &token).await?;
        let format = parse_format(format.as_deref())?;
        let content = subscription::render(
            format,
            &state.subscription_config,
            &user,
            state.master_secret.as_deref(),
        )
        .map_err(|error| async_graphql::Error::new(format!("render subscription: {error}")))?;

        Ok(SubscriptionPayload {
            uuid: user.uuid,
            format: format_name(format).to_owned(),
            extension: format.extension().to_owned(),
            content,
        })
    }
}

#[derive(Default)]
pub struct MutationRoot;

#[Object]
impl MutationRoot {
    async fn register(&self, ctx: &Context<'_>, input: RegisterInput) -> Result<RegisterPayload> {
        validate_required("name", &input.name)?;
        validate_required("email", &input.email)?;
        validate_required("password", &input.password)?;
        validate_required("inviteCode", &input.invite_code)?;

        let state = ctx.data::<AppState>()?;
        validate_email_allowed(state, &input.email)?;
        let secrets = generate_user_secrets(&input.password)?;
        let invite_code = input.invite_code.trim();
        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(|error| async_graphql::Error::new(format!("begin register: {error}")))?;

        let inviter_uuid: Uuid = sqlx::query_scalar(
            r#"
            SELECT user_uuid
            FROM user_invites
            WHERE code = $1
            "#,
        )
        .bind(invite_code)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| async_graphql::Error::new(format!("query invite code: {error}")))?
        .ok_or_else(invalid_invite_code_error)?;

        let row = sqlx::query(
            r#"
            INSERT INTO users (
                name,
                email,
                password_hash,
                token,
                token_prefix,
                invited_by_uuid
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING uuid
            "#,
        )
        .bind(&input.name)
        .bind(&input.email)
        .bind(&secrets.password_hash)
        .bind(&secrets.token)
        .bind(&secrets.token_prefix)
        .bind(inviter_uuid)
        .fetch_one(&mut *tx)
        .await
        .map_err(|error| async_graphql::Error::new(format!("register user: {error}")))?;
        tx.commit()
            .await
            .map_err(|error| async_graphql::Error::new(format!("commit register: {error}")))?;

        Ok(RegisterPayload {
            uuid: row
                .try_get("uuid")
                .map_err(|error| async_graphql::Error::new(format!("read uuid: {error}")))?,
            token: secrets.token,
            token_prefix: secrets.token_prefix,
        })
    }

    async fn reset_invite_code(
        &self,
        ctx: &Context<'_>,
        token: String,
    ) -> Result<InviteCodePayload> {
        validate_required("token", &token)?;

        let state = ctx.data::<AppState>()?;
        let user = load_enabled_user_by_token(state, &token).await?;
        let invite = generate_invite_code();

        sqlx::query(
            r#"
            INSERT INTO user_invites (user_uuid, code, code_prefix)
            VALUES ($1, $2, $3)
            ON CONFLICT (user_uuid) DO UPDATE
            SET code = EXCLUDED.code,
                code_prefix = EXCLUDED.code_prefix,
                rotated_at = now()
            "#,
        )
        .bind(user.uuid)
        .bind(&invite.invite_code)
        .bind(&invite.invite_code_prefix)
        .execute(&state.pool)
        .await
        .map_err(|error| async_graphql::Error::new(format!("reset invite code: {error}")))?;

        Ok(InviteCodePayload {
            uuid: user.uuid,
            invite_code: invite.invite_code,
            invite_code_prefix: invite.invite_code_prefix,
        })
    }

    async fn login(&self, ctx: &Context<'_>, input: LoginInput) -> Result<LoginPayload> {
        validate_required("email", &input.email)?;
        validate_required("password", &input.password)?;

        let state = ctx.data::<AppState>()?;
        let row = sqlx::query(
            r#"
            SELECT uuid, name, email, password_hash, token, token_prefix
            FROM users
            WHERE email = $1
              AND enabled = TRUE
            "#,
        )
        .bind(&input.email)
        .fetch_optional(&state.pool)
        .await
        .map_err(|error| async_graphql::Error::new(format!("login user: {error}")))?
        .ok_or_else(invalid_login_error)?;

        let password_hash: String = row
            .try_get("password_hash")
            .map_err(|error| async_graphql::Error::new(format!("read password_hash: {error}")))?;
        let password_matches = verify_password(&input.password, &password_hash)
            .map_err(|error| async_graphql::Error::new(format!("verify password: {error}")))?;
        if !password_matches {
            return Err(invalid_login_error());
        }

        Ok(LoginPayload {
            uuid: row
                .try_get("uuid")
                .map_err(|error| async_graphql::Error::new(format!("read uuid: {error}")))?,
            name: row
                .try_get("name")
                .map_err(|error| async_graphql::Error::new(format!("read name: {error}")))?,
            email: row
                .try_get("email")
                .map_err(|error| async_graphql::Error::new(format!("read email: {error}")))?,
            token: row
                .try_get("token")
                .map_err(|error| async_graphql::Error::new(format!("read token: {error}")))?,
            token_prefix: row.try_get("token_prefix").map_err(|error| {
                async_graphql::Error::new(format!("read token_prefix: {error}"))
            })?,
        })
    }
}

#[derive(async_graphql::InputObject)]
pub struct RegisterInput {
    pub name: String,
    pub email: String,
    pub password: String,
    pub invite_code: String,
}

#[derive(async_graphql::InputObject)]
pub struct LoginInput {
    pub email: String,
    pub password: String,
}

#[derive(SimpleObject)]
pub struct RegisterPayload {
    pub uuid: Uuid,
    pub token: String,
    pub token_prefix: String,
}

#[derive(SimpleObject)]
pub struct LoginPayload {
    pub uuid: Uuid,
    pub name: String,
    pub email: String,
    pub token: String,
    pub token_prefix: String,
}

#[derive(SimpleObject)]
pub struct InviteCodePayload {
    pub uuid: Uuid,
    pub invite_code: String,
    pub invite_code_prefix: String,
}

#[derive(SimpleObject)]
pub struct SubscriptionPayload {
    pub uuid: Uuid,
    pub format: String,
    pub extension: String,
    pub content: String,
}

pub fn schema(state: AppState) -> AppSchema {
    Schema::build(QueryRoot, MutationRoot, EmptySubscription)
        .data(state)
        .finish()
}

pub fn router(schema: AppSchema) -> Router {
    Router::new()
        .route("/", get(playground))
        .route("/graphql", get(playground).post(graphql))
        .route("/subscription/{format}", get(subscription_file))
        .with_state(schema)
}

async fn graphql(
    State(schema): State<AppSchema>,
    Json(request): Json<async_graphql::Request>,
) -> Json<async_graphql::Response> {
    Json(schema.execute(request).await)
}

async fn playground() -> Html<String> {
    Html(async_graphql::http::playground_source(
        async_graphql::http::GraphQLPlaygroundConfig::new("/graphql"),
    ))
}

#[derive(Deserialize)]
struct SubscriptionQuery {
    token: String,
}

async fn subscription_file(
    State(schema): State<AppSchema>,
    Path(format): Path<String>,
    Query(query): Query<SubscriptionQuery>,
) -> Response {
    match render_subscription_file(&schema, &query.token, &format).await {
        Ok((format, content)) => {
            let mut response = content.into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(content_type(format)),
            );
            response
        }
        Err(error) => (StatusCode::UNAUTHORIZED, error.message).into_response(),
    }
}

async fn render_subscription_file(
    schema: &AppSchema,
    token: &str,
    format: &str,
) -> Result<(SubscriptionFormat, String)> {
    let state = schema
        .data::<AppState>()
        .ok_or_else(|| async_graphql::Error::new("missing app state"))?;
    let user = load_enabled_user_by_token(state, token).await?;
    let format = parse_format(Some(format))?;
    let content = subscription::render(
        format,
        &state.subscription_config,
        &user,
        state.master_secret.as_deref(),
    )
    .map_err(|error| async_graphql::Error::new(format!("render subscription: {error}")))?;

    Ok((format, content))
}

async fn load_enabled_user_by_token(state: &AppState, token: &str) -> Result<User> {
    let row = sqlx::query(
        r#"
        SELECT uuid, name, token
        FROM users
        WHERE token = $1
          AND enabled = TRUE
        "#,
    )
    .bind(token)
    .fetch_optional(&state.pool)
    .await
    .map_err(|error| async_graphql::Error::new(format!("query user: {error}")))?
    .ok_or_else(|| async_graphql::Error::new("invalid token"))?;

    Ok(User {
        uuid: row
            .try_get("uuid")
            .map_err(|error| async_graphql::Error::new(format!("read uuid: {error}")))?,
        name: row
            .try_get("name")
            .map_err(|error| async_graphql::Error::new(format!("read name: {error}")))?,
        token: row
            .try_get("token")
            .map_err(|error| async_graphql::Error::new(format!("read token: {error}")))?,
    })
}

fn parse_format(format: Option<&str>) -> Result<SubscriptionFormat> {
    match format {
        Some(value) => SubscriptionFormat::parse(value)
            .ok_or_else(|| async_graphql::Error::new(format!("unknown format: {value}"))),
        None => Ok(SubscriptionFormat::SingBox),
    }
}

fn format_name(format: SubscriptionFormat) -> &'static str {
    match format {
        SubscriptionFormat::Clash => "clash",
        SubscriptionFormat::SingBox => "sing-box",
        SubscriptionFormat::Shadowrocket => "shadowrocket",
    }
}

fn content_type(format: SubscriptionFormat) -> &'static str {
    match format {
        SubscriptionFormat::Clash => "text/yaml; charset=utf-8",
        SubscriptionFormat::SingBox => "application/json; charset=utf-8",
        SubscriptionFormat::Shadowrocket => "text/plain; charset=utf-8",
    }
}

fn validate_required(name: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(async_graphql::Error::new(format!("{name} cannot be empty")));
    }
    Ok(())
}

fn validate_email_allowed(state: &AppState, email: &str) -> Result<()> {
    if state.email_allow_list.is_empty() || state.email_allow_list.contains(&normalize_email(email))
    {
        return Ok(());
    }

    Err(async_graphql::Error::new(
        "email is not allowed to register",
    ))
}

fn invalid_login_error() -> async_graphql::Error {
    async_graphql::Error::new("invalid email or password")
}

fn invalid_invite_code_error() -> async_graphql::Error {
    async_graphql::Error::new("invalid invite code")
}
