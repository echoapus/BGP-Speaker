use std::env;
use std::path::Path;

use bgp_speaker::{config::Config, controller::run};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("Usage: megaphone --config <path>");
        return;
    }

    let path = args
        .windows(2)
        .find(|pair| pair[0] == "--config")
        .map(|pair| pair[1].as_str())
        .unwrap_or("config.toml");

    let config = match Config::from_file(Path::new(path)) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("configuration error: {error}");
            std::process::exit(2);
        }
    };

    if let Err(error) = run(config) {
        eprintln!("runtime error: {error}");
        std::process::exit(1);
    }
}
