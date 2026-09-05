#[derive(Clone, Debug)]
enum Token {
    AnySequence,
    AnyCharacter,
    Literal(char),
    Class {
        negated: bool,
        members: Vec<ClassMember>,
    },
}

#[derive(Clone, Debug)]
enum ClassMember {
    Character(char),
    Range(char, char),
}

/// Compiled Redis-style glob pattern.
///
/// Matching is iterative so large patterns cannot recurse through the process
/// stack. Consecutive `*` tokens are collapsed during compilation.
#[derive(Clone, Debug)]
pub(crate) struct GlobPattern {
    tokens: Vec<Token>,
}

impl GlobPattern {
    pub(crate) fn new(pattern: &str) -> Self {
        let chars: Vec<char> = pattern.chars().collect();
        let mut tokens = Vec::with_capacity(chars.len());
        let mut pos = 0usize;
        while pos < chars.len() {
            match chars[pos] {
                '*' => {
                    if !matches!(tokens.last(), Some(Token::AnySequence)) {
                        tokens.push(Token::AnySequence);
                    }
                    pos += 1;
                }
                '?' => {
                    tokens.push(Token::AnyCharacter);
                    pos += 1;
                }
                '[' => match parse_class(&chars, pos) {
                    Some((token, next)) => {
                        tokens.push(token);
                        pos = next;
                    }
                    None => {
                        tokens.push(Token::Literal('['));
                        pos += 1;
                    }
                },
                value => {
                    tokens.push(Token::Literal(value));
                    pos += 1;
                }
            }
        }
        Self { tokens }
    }

    pub(crate) fn matches(&self, value: &str) -> bool {
        if self.tokens.len() == 1 && matches!(self.tokens[0], Token::AnySequence) {
            return true;
        }
        let value: Vec<char> = value.chars().collect();
        let Some(first_sequence) = self
            .tokens
            .iter()
            .position(|token| matches!(token, Token::AnySequence))
        else {
            return self.tokens.len() == value.len()
                && self
                    .tokens
                    .iter()
                    .zip(&value)
                    .all(|(token, value)| token_matches(token, *value));
        };
        let last_sequence = self
            .tokens
            .iter()
            .rposition(|token| matches!(token, Token::AnySequence))
            .expect("first sequence exists");
        let suffix_len = self.tokens.len() - last_sequence - 1;
        if value.len() < first_sequence.saturating_add(suffix_len) {
            return false;
        }
        if !self.tokens[..first_sequence]
            .iter()
            .zip(&value[..first_sequence])
            .all(|(token, value)| token_matches(token, *value))
        {
            return false;
        }
        if !self.tokens[last_sequence + 1..]
            .iter()
            .zip(&value[value.len() - suffix_len..])
            .all(|(token, value)| token_matches(token, *value))
        {
            return false;
        }
        if first_sequence == last_sequence {
            return true;
        }

        let tokens = &self.tokens[first_sequence..=last_sequence];
        let value = &value[first_sequence..value.len() - suffix_len];
        let mut value_pos = 0usize;
        let mut token_pos = 0usize;
        let mut sequence_pos = None;
        let mut sequence_match = 0usize;

        while value_pos < value.len() {
            if token_pos < tokens.len() && token_matches(&tokens[token_pos], value[value_pos]) {
                token_pos += 1;
                value_pos += 1;
            } else if token_pos < tokens.len() && matches!(tokens[token_pos], Token::AnySequence) {
                sequence_pos = Some(token_pos);
                token_pos += 1;
                sequence_match = value_pos;
            } else if let Some(sequence) = sequence_pos {
                sequence_match += 1;
                value_pos = sequence_match;
                token_pos = sequence + 1;
            } else {
                return false;
            }
        }

        while token_pos < tokens.len() && matches!(tokens[token_pos], Token::AnySequence) {
            token_pos += 1;
        }
        token_pos == tokens.len()
    }
}

fn parse_class(chars: &[char], start: usize) -> Option<(Token, usize)> {
    let mut pos = start + 1;
    let negated = pos < chars.len() && chars[pos] == '^';
    if negated {
        pos += 1;
    }
    let mut members = Vec::new();
    while pos < chars.len() && chars[pos] != ']' {
        if pos + 2 < chars.len() && chars[pos + 1] == '-' && chars[pos + 2] != ']' {
            members.push(ClassMember::Range(chars[pos], chars[pos + 2]));
            pos += 3;
        } else {
            members.push(ClassMember::Character(chars[pos]));
            pos += 1;
        }
    }
    if pos >= chars.len() || members.is_empty() {
        return None;
    }
    Some((Token::Class { negated, members }, pos + 1))
}

fn token_matches(token: &Token, value: char) -> bool {
    match token {
        Token::AnyCharacter => true,
        Token::Literal(expected) => *expected == value,
        Token::Class { negated, members } => {
            let found = members.iter().any(|member| match member {
                ClassMember::Character(expected) => *expected == value,
                ClassMember::Range(start, end) => value >= *start && value <= *end,
            });
            found != *negated
        }
        Token::AnySequence => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(actual: &[char], pattern: &[char]) -> bool {
        let mut rows = vec![vec![false; actual.len() + 1]; pattern.len() + 1];
        rows[0][0] = true;
        for pattern_pos in 1..=pattern.len() {
            if pattern[pattern_pos - 1] == '*' {
                rows[pattern_pos][0] = rows[pattern_pos - 1][0];
            }
            for value_pos in 1..=actual.len() {
                rows[pattern_pos][value_pos] = match pattern[pattern_pos - 1] {
                    '*' => rows[pattern_pos - 1][value_pos] || rows[pattern_pos][value_pos - 1],
                    '?' => rows[pattern_pos - 1][value_pos - 1],
                    value => rows[pattern_pos - 1][value_pos - 1] && value == actual[value_pos - 1],
                };
            }
        }
        rows[pattern.len()][actual.len()]
    }

    fn strings(alphabet: &[char], max_len: usize) -> Vec<String> {
        let mut values = vec![String::new()];
        let mut frontier = vec![String::new()];
        for _ in 0..max_len {
            let mut next = Vec::new();
            for prefix in &frontier {
                for value in alphabet {
                    let mut item = prefix.clone();
                    item.push(*value);
                    values.push(item.clone());
                    next.push(item);
                }
            }
            frontier = next;
        }
        values
    }

    #[test]
    fn supports_literals_wildcards_and_classes() {
        for (pattern, value, expected) in [
            ("*", "anything", true),
            ("user:*", "user:123", true),
            ("h?llo", "hello", true),
            ("h[ae]llo", "hallo", true),
            ("h[^e]llo", "hello", false),
            ("item-[0-9]", "item-7", true),
            ("literal[", "literal[", true),
            ("a**b", "axxb", true),
            ("a*b", "axxc", false),
        ] {
            assert_eq!(GlobPattern::new(pattern).matches(value), expected);
        }
    }

    #[test]
    fn large_pattern_does_not_recurse() {
        let pattern = "*?".repeat(50_000);
        let value = "a".repeat(50_000);
        assert!(GlobPattern::new(&pattern).matches(&value));

        let pattern = format!("{}b", "a".repeat(100_000));
        let value = format!("{}c", "a".repeat(100_000));
        assert!(!GlobPattern::new(&pattern).matches(&value));
    }

    #[test]
    fn large_star_suffix_is_bounded() {
        let pattern = format!("*{}b", "a".repeat(10_000));
        let value = "a".repeat(20_000);
        assert!(!GlobPattern::new(&pattern).matches(&value));
    }

    #[test]
    fn iterative_matcher_matches_reference_exhaustively() {
        let values = strings(&['a', 'b'], 5);
        let patterns = strings(&['a', 'b', '*', '?'], 5);
        for value in &values {
            for pattern in &patterns {
                let value_chars: Vec<char> = value.chars().collect();
                let pattern_chars: Vec<char> = pattern.chars().collect();
                assert_eq!(
                    GlobPattern::new(pattern).matches(value),
                    reference(&value_chars, &pattern_chars),
                    "value={value:?}, pattern={pattern:?}"
                );
            }
        }
    }
}
