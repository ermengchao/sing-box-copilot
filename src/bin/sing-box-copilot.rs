use std::env;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    sing_box_copilot::cli::run(&args).await
}
