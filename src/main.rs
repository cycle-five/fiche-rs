use fiche_rs::fiche_run;
use fiche_rs::{Args, FicheSettings};

use clap::Parser;

#[cfg(not(tarpaulin_include))]
/// The main function
fn main() -> Result<(), String> {
    // Define the command-line interface using the clap crate

    // Parse the command-line arguments
    let args = Args::parse();

    let settings = FicheSettings::new(&args);
    fiche_run(settings)
}
