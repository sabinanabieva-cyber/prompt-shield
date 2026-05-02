//Author: Sabina Nabieva
//scanner.rs: Core Detection Engine
//
// Scans text content for indirect prompt injection attacks.
// Loads patterns from patterns.toml and checks each line
// for known injection phrases, hidden HTML text, and
// suspicious HTML comments.
//
// Detection types:
//   - Plain text pattern matching (phrase lookup)
//   - Hidden HTML detection (color:white, font-size:0, display:none)
//   - HTML comment injection (<!-- hidden instructions -->)
//
// Sources for patterns:
//   - OWASP LLM Top 10
//   - Known jailbreak attack archives
//   - Original research testing against live AI systems

use serde::Deserialize;
use std::fs;

/// One pattern loaded from patterns.toml
#[derive(Debug, Deserialize, Clone)]
pub struct Pattern {
    pub phrase: String,
    pub category: String,
    pub severity: String,
}

/// A match found in the scanned content
#[derive(Debug)]
pub struct Match {
    pub pattern: Pattern,
    pub line_number: usize,
    pub line_content: String,
    pub match_type: MatchType,
}

#[derive(Debug)]
pub enum MatchType {
    PlainText,
    HiddenHtmlStyle,  // style="color:white" or font-size:0
    HtmlComment,      // <!-- hidden instruction -->
}

/// Wrapper to deserialize the toml file
#[derive(Deserialize)]
struct PatternsFile {
    patterns: Vec<Pattern>,
}

/// Load patterns from a toml file
pub fn load_patterns(path: &str) -> Result<Vec<Pattern>, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path, e))?;

    let parsed: PatternsFile = toml::from_str(&content)
        .map_err(|e| format!("Failed to parse patterns.toml: {}", e))?;

    Ok(parsed.patterns)
}

/// Scan content for all known injection patterns
pub fn scan(content: &str, patterns: &[Pattern]) -> Vec<Match> {
    let mut matches = Vec::new();
    let lower_content = content.to_lowercase();

    for (line_number, line) in content.lines().enumerate() {
        let lower_line = line.to_lowercase();

        // Check each pattern against this line
        for pattern in patterns {
            if lower_line.contains(&pattern.phrase.to_lowercase()) {
                let match_type = detect_match_type(line);
                matches.push(Match {
                  pattern: pattern.clone(),
                    line_number: line_number + 1,
                    line_content: line.trim().to_string(),
                    match_type,
                });
            }
        }
         // Check for hidden HTML text (color:white, font-size:0, display:none)
        if is_hidden_html(line) && !lower_line.is_empty() {
            // Only flag if not already caught by a pattern
            let already_flagged = matches.iter().any(|m| m.line_number == line_number + 1);
            if !already_flagged && lower_line.len() > 10 {
                matches.push(Match {
                    pattern: Pattern {
                        phrase: "hidden html element".to_string(),
                        category: "Hidden Content".to_string(),
                        severity: "HIGH".to_string(),
                    },
                    line_number: line_number + 1,
                    line_content: line.trim().to_string(),
                    match_type: MatchType::HiddenHtmlStyle,
                });
            }
        }

        // Check for suspicious HTML comments
        if line.contains("<!--") && contains_instruction_language(&lower_line) {
            matches.push(Match {
                pattern: Pattern {
                    phrase: "instruction in html comment".to_string(),
                    category: "Hidden Content".to_string(),
                    severity: "HIGH".to_string(),
                },
                line_number: line_number + 1,
                line_content: line.trim().to_string(),
                match_type: MatchType::HtmlComment,
            });
        }
    }

    // Also scan full content for multi-line patterns
    let _ = lower_content; // suppress warning

    matches
}

/// Detect what kind of match this is
fn detect_match_type(line: &str) -> MatchType {
    if is_hidden_html(line) {
        MatchType::HiddenHtmlStyle
    } else if line.contains("<!--") {
        MatchType::HtmlComment
    } else {
        MatchType::PlainText
    }
}
/// Check if an HTML line is trying to hide content visually
fn is_hidden_html(line: &str) -> bool {
    let lower = line.to_lowercase();
    lower.contains("color:white")
        || lower.contains("color: white")
        || lower.contains("font-size:0")
        || lower.contains("font-size: 0")
        || lower.contains("display:none")
        || lower.contains("display: none")
        || lower.contains("visibility:hidden")
        || lower.contains("opacity:0")
        || lower.contains("font-size:1px")
        || lower.contains("color:#fff")
        || lower.contains("color:#ffffff")
}

/// Check if text contains language that sounds like instructions
fn contains_instruction_language(lower_line: &str) -> bool {
    lower_line.contains("ignore")
        || lower_line.contains("instruction")
        || lower_line.contains("system")
        || lower_line.contains("prompt")
        || lower_line.contains("assistant")
        || lower_line.contains("you must")
        || lower_line.contains("you are")
        || lower_line.contains("do not")
        || lower_line.contains("always")
        || lower_line.contains("never")
}

