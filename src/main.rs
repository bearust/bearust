use clap::Parser;
fn main() {
    if let Err(error) = bearust::cli::run(bearust::cli::Cli::parse()) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
