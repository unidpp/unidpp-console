//! The console binary.

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    match unidpp_console::Config::from_env() {
        Ok(config) => match unidpp_console::run(config).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("unidpp-console: {e}");
                ExitCode::FAILURE
            }
        },
        Err(e) => {
            eprintln!("unidpp-console: {e}");
            ExitCode::FAILURE
        }
    }
}
