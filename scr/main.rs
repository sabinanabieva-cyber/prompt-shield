// main.rs:  Entry Point and CLI Interface
//
// Defines the command-line interface for Prompt Shield using clap.
// Supports two subcommands:
//
//   scan  <file>: scans a file and prints a threat report
//   clean <file>:scans a file, prints report, and saves a
//                   sanitized version safe to pass to an AI
//
// Usage:
//   cargo run -- scan  test_samples/attack1_cookie_recipe.html
//   cargo run -- clean test_samples/attack2_meeting_notes.txt
//
// All detection logic lives in scanner.rs
// All cleaning logic lives in cleaner.rs
// All report formatting lives in reporter.rs

mod scanner;
mod cleaner;
mod reporter;

use clap::{Parser, Subcommand};
use std::fs;

#[derive(Parser)]
#[command(name = "prompt-shield")]
#[command(about = "Detects and removes indirect prompt injection attacks from content")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a file for prompt injection threats
    Scan {
        /// Path to the file to scan
        file: String,
    },
    /// Scan and clean a file, outputting safe version
    Clean {
        /// Path to the file to clean
        file: String,
    },
}

fn main() {
    let cli = Cli::parse();

    // Load patterns from patterns.toml
    let patterns = scanner::load_patterns("patterns.toml")
        .expect("Could not load patterns.toml — make sure it exists in the current directory");

    match cli.command {
        Commands::Scan { file } => {
            let content = fs::read_to_string(&file)
                .unwrap_or_else(|_| panic!("Could not read file: {}", file));

            let matches = scanner::scan(&content, &patterns);
            reporter::print_report(&file, &content, &matches);
        }

        Commands::Clean { file } => {
            let content = fs::read_to_string(&file)
                .unwrap_or_else(|_| panic!("Could not read file: {}", file));

            let matches = scanner::scan(&content, &patterns);
            reporter::print_report(&file, &content, &matches);

            let cleaned = cleaner::clean(&content, &matches);
            let output_path = format!("{}.cleaned.txt", file);
            fs::write(&output_path, &cleaned)
                .expect("Could not write cleaned output file");

            println!("\n🧹 Cleaned version saved to: {}", output_path);
            println!("   You can now safely pass this to an AI.\n");
        }
    }
}
