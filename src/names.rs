pub const MAX_NAME: usize = 64;

/// Secret names: 1 to 64 of `a-z 0-9 . _ -`, not starting with `.` or `-`.
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME
        && !s.starts_with(['.', '-'])
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for ok in ["github", "stripe-live", "aws.prod_1"] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in ["", "GitHub", "a b", "../x", ".hidden", "-flag", "a\nb", &"a".repeat(65)] {
            assert!(!valid_name(bad), "{bad:?}");
        }
    }
}
