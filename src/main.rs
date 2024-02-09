use fiche_rs::fiche_run;
use fiche_rs::{Args, FicheSettings};

use clap::Parser;

#[cfg(not(shuttle))]
#[cfg(not(tarpaulin_include))]
/// The main function
fn main() -> Result<(), String> {
    // Define the command-line interface using the clap crate

    // Parse the command-line arguments
    let args = Args::parse();

    let settings = FicheSettings::new(&args);
    fiche_run(settings)
}

#[cfg(shuttle)]
#[cfg(not(tarpaulin_include))]
#[shuttle_runtime::main]
async fn main() -> shuttle_axum::ShuttleAxum {
    let router = Router::new()
        .route("/", get(hello_world))
        .nest_service("/assets", ServeDir::new("assets"));

    Ok(router.into())
}
