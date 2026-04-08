use std::collections::HashMap;

/// Calculate the Shannon entropy of a string.
/// Returns bits per character.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq: HashMap<char, usize> = HashMap::new();
    let len = s.len() as f64;

    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }

    freq.values().fold(0.0, |entropy, &count| {
        let p = count as f64 / len;
        entropy - p * p.log2()
    })
}

/// Check if a value looks like a template variable.
pub fn is_template_variable(value: &str) -> bool {
    let trimmed = value.trim();
    (trimmed.starts_with("{{") && trimmed.ends_with("}}"))
        || (trimmed.starts_with("${") && trimmed.ends_with("}"))
        || (trimmed.starts_with('<') && trimmed.ends_with('>') && !trimmed.contains(' '))
}

/// Check if a value is a common placeholder that should not be flagged.
pub fn is_placeholder(value: &str) -> bool {
    let lower = value.to_lowercase();
    let placeholders = [
        "your_api_key_here",
        "your_token_here",
        "your_secret_here",
        "xxx",
        "example",
        "test",
        "dummy",
        "fake",
        "placeholder",
        "changeme",
        "replace_me",
        "todo",
        "fixme",
        "insert_here",
    ];
    placeholders.iter().any(|p| lower.contains(p))
}

/// Check if a value is obviously non-secret.
pub fn is_obviously_non_secret(value: &str) -> bool {
    let trimmed = value.trim();

    // Content types, booleans, numbers
    if trimmed.starts_with("application/")
        || trimmed.starts_with("text/")
        || trimmed.starts_with("multipart/")
    {
        return true;
    }

    matches!(trimmed, "true" | "false" | "null" | "none" | "undefined")
        || trimmed.parse::<f64>().is_ok()
}

/// Determine if a string is a high-entropy potential secret.
/// Returns true if the value is suspicious.
pub fn is_high_entropy_secret(value: &str) -> bool {
    let trimmed = value.trim();

    if trimmed.len() <= 20 {
        return false;
    }

    if is_template_variable(trimmed) || is_placeholder(trimmed) || is_obviously_non_secret(trimmed)
    {
        return false;
    }

    shannon_entropy(trimmed) > 4.5
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_low_for_simple_strings() {
        assert!(shannon_entropy("aaaaaaa") < 1.0);
        assert!(shannon_entropy("hello") < 3.0);
    }

    #[test]
    fn test_entropy_high_for_random_strings() {
        assert!(shannon_entropy("a8Kp2xZq9LmN4wRtY7vBcE3fGhJsD6uXoP") > 4.0);
    }

    #[test]
    fn test_template_variable_detection() {
        assert!(is_template_variable("{{token}}"));
        assert!(is_template_variable("${API_KEY}"));
        assert!(is_template_variable("<api_key>"));
        assert!(!is_template_variable("sk_live_abc123"));
        assert!(!is_template_variable("<this has spaces>"));
    }

    #[test]
    fn test_placeholder_detection() {
        assert!(is_placeholder("your_api_key_here"));
        assert!(is_placeholder("xxx"));
        assert!(is_placeholder("EXAMPLE_TOKEN_HERE"));
        assert!(!is_placeholder("sk_live_abc123xyz456"));
    }

    #[test]
    fn test_non_secret_detection() {
        assert!(is_obviously_non_secret("application/json"));
        assert!(is_obviously_non_secret("true"));
        assert!(is_obviously_non_secret("42"));
        assert!(!is_obviously_non_secret("sk_live_abc123xyz456"));
    }
}
