pub mod routes;
pub mod state;

pub async fn run_from_env() -> anyhow::Result<()> {
    let state = state::AppState::from_env().await?;
    let bind = format!("{}:{}", state.bind_config.host, state.bind_config.port);
    let schema = routes::schema(state);
    let router = routes::router(schema);
    let listener = tokio::net::TcpListener::bind(&bind).await?;

    tracing::info!(bind, "starting GraphQL server");
    axum::serve(listener, router).await?;

    Ok(())
}
