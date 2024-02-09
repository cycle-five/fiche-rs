use fiche_rs::fiche_run;
use fiche_rs::{Args, FicheSettings};

use clap::Parser;

#[cfg(shuttle_rocket)]
use {
    rocket::fs::relative,
    rocket::fs::NamedFile,
    std::path::{Path, PathBuf},
};

#[cfg(all(not(shuttle_rocket), not(shuttle_axum)))]
#[cfg(not(tarpaulin_include))]
/// The main function
fn main() -> Result<(), String> {
    // Define the command-line interface using the clap crate

    // Parse the command-line arguments
    let args = Args::parse();

    let settings = FicheSettings::new(&args);
    fiche_run(settings)
}

#[cfg(shuttle_axum)]
#[cfg(not(tarpaulin_include))]
#[shuttle_runtime::main]
async fn main() -> shuttle_axum::ShuttleAxum {
    let router = Router::new()
        .route("/", get(hello_world))
        .nest_service("/assets", ServeDir::new("assets"));

    Ok(router.into())
}

#[cfg(shuttle_rocket)]
#[rocket::get("/<path..>")]
pub async fn serve(mut path: PathBuf) -> Option<NamedFile> {
    path.set_extension("html");
    let mut path = Path::new(relative!("assets")).join(path);
    if path.is_dir() {
        path.push("index.html");
    }

    NamedFile::open(path).await.ok()
}

#[cfg(shuttle_rocket)]
#[shuttle_runtime::main]
async fn rocket() -> shuttle_rocket::ShuttleRocket {
    let rocket = rocket::build().mount("/", rocket::routes![serve]);

    Ok(rocket.into())
}
