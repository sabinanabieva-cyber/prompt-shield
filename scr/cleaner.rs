// cleaner.rs: Content Sanitizer
//
// Takes the raw content and a list of matches found by scanner.rs
// and removes or replaces all malicious lines.
//
// Cleaning behavior by match type:
//   - HiddenHtmlStyle : line is deleted entirely (was invisible anyway)
//   - HtmlComment : line is deleted entirely
//   - PlainText : line is replaced with [REDACTED] marker
//
// Also removes orphaned closing tags (</p>, </div>, </span>)
// left behind after their parent malicious line is deleted.
//
// Output is a clean version of the original content
// safe to pass to an AI agent.

use crate::scanner::{Match, MatchType};

/// Remove all matched threats from content
pub fn clean(content: &str, matches: &[Match]) -> String {
    let bad_lines: std::collections::HashSet<usize> = matches
        .iter()
        .map(|m| m.line_number)
        .collect();

    let lines: Vec<&str> = content.lines().collect();
    let mut extra_remove: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for &bad_line in &bad_lines {
        let next = bad_line;
        if next < lines.len() {
            let next_line = lines[next].trim();
            if next_line == "</p>" || next_line == "</div>" || next_line == "</span>" {
                extra_remove.insert(next + 1);
            }
        }
    }

    let cleaned: Vec<String> = content
        .lines()
        .enumerate()
        .map(|(i, line)| {
            let line_number = i + 1;
            if bad_lines.contains(&line_number) || extra_remove.contains(&line_number) {
                match get_match_type_for_line(matches, line_number) {
                    Some(MatchType::HiddenHtmlStyle) => String::new(),
                    Some(MatchType::HtmlComment) => String::new(),
                    _ => {
                        if extra_remove.contains(&line_number) {
                            String::new()
                        } else {
                            String::from("[REDACTED: prompt injection removed]")
                        }
                    }
                }
            } else {
                line.to_string()
            }
        })
        .collect();

    let mut result = String::new();
    let mut last_was_blank = false;

    for line in &cleaned {
        let is_blank = line.trim().is_empty();
        if is_blank && last_was_blank {
            continue;
        }
        result.push_str(line);
        result.push('\n');
        last_was_blank = is_blank;
    }

    result
}

fn get_match_type_for_line(matches: &[Match], line_number: usize) -> Option<&MatchType> {
    matches
        .iter()
        .find(|m| m.line_number == line_number)
        .map(|m| &m.match_type)
}
