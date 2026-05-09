#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sing_box_copilot::server::run_from_env().await
}
