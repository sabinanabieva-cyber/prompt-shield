// reporter.rs: Threat Report Formatter
//
// Takes the scan results from scanner.rs and prints a
// formatted threat report to the terminal.
//
// Report includes:
//   - File name and total line count
//   - Total number of threats found
//   - Each threat with line number, matched phrase, and severity
//   - Summary of HIGH / MEDIUM / LOW counts
//   - Summary of categories detected
//   - Final recommendation (safe to use or do not pass to AI)
//
// Uses the `colored` crate for terminal colors:
//   - RED    HIGH severity threats
//   - YELLOW  MEDIUM severity threats
//   - GREEN  clean / safe results

use colored::*;
use crate::scanner::Match;

/// Print a full threat report to the terminal
pub fn print_report(filename: &str, content: &str, matches: &[Match]) {
    let total_lines = content.lines().count();

    println!();
    println!("{}", "━".repeat(55).bright_blue());
    println!("  {}  Prompt Shield Scanner");
    println!("{}", "━".repeat(55).bright_blue());
    println!("  File:       {}", filename.cyan());
    println!("  Lines:      {}", total_lines);
    println!("  Threats:    {}", format_threat_count(matches.len()));
    println!("{}", "━".repeat(55).bright_blue());

    if matches.is_empty() {
        println!();
        println!("  {} No threats detected. Content appears safe.", "SAFE".green());
        println!();
        return;
    }

    println!();

    // Print each match
    for (i, m) in matches.iter().enumerate() {
        let severity_label = format_severity(&m.pattern.severity);
        println!(
            "  {} Threat #{} — {} [{}]",
            "THREAT",
            i + 1,
            m.pattern.category.bold(),
            severity_label
        );
        println!("     Line {}:  {}", m.line_number, m.line_content.dimmed());
        println!("     Matched: \"{}\"", m.pattern.phrase.yellow());
        println!();
     }

    println!("{}", "━".repeat(55).bright_blue());
    println!("  Summary:");
    print_summary(matches);
    println!("{}", "━".repeat(55).bright_blue());
    println!();

    // Recommendation
    if has_high_severity(matches) {
        println!(
            "  {} {} HIGH severity threats found.",
            "⛔".red(),
            count_severity(matches, "HIGH")
        );
        println!("     Do NOT pass this content to an AI without cleaning.");
    } else {
        println!(
            "  {} Only low/medium threats found. Review before passing to AI.",
            "⚠️ ".yellow()
        );
    }
    println!();
}

fn format_threat_count(count: usize) -> ColoredString {
    if count == 0 {
        "0 (clean)".green()
    } else if count <= 2 {
        format!("{} threats", count).yellow()
    } else {
        format!("{} threats", count).red()
    }
  }

fn format_severity(severity: &str) -> ColoredString {
    match severity {
        "HIGH" => "HIGH".red().bold(),
        "MEDIUM" => "MEDIUM".yellow(),
        "LOW" => "LOW".green(),
        _ => severity.normal(),
    }
}

fn has_high_severity(matches: &[Match]) -> bool {
    matches.iter().any(|m| m.pattern.severity == "HIGH")
}

fn count_severity(matches: &[Match], severity: &str) -> usize {
    matches.iter().filter(|m| m.pattern.severity == severity).count()
}

fn print_summary(matches: &[Match]) {
    // Count by category
    let mut categories: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for m in matches {
        *categories.entry(m.pattern.category.as_str()).or_insert(0) += 1;
    }

    let high = count_severity(matches, "HIGH");
    let medium = count_severity(matches, "MEDIUM");
    let low = count_severity(matches, "LOW");

    if high > 0 {
        println!("  {}  High:   {}", "🔴", high);
    }
    if medium > 0 {
        println!("  {}  Medium: {}", "🟡", medium);
    }
    if low > 0 {
        println!("  {}  Low:    {}", "🟢", low);
    }

    println!();
    println!("  Categories detected:");
    let mut cats: Vec<_> = categories.iter().collect();
    cats.sort_by_key(|(k, _)| *k);
    for (cat, count) in cats {
        println!("    • {} ({})", cat, count);
    }
}
