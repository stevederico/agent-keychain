//! Finds secrets sitting in plain files (`.env`, shell config, tool credential files), so
//! they can be moved into the vault. Reports where they are; never prints a full value.

use crate::names::valid_name;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Known token shapes: (prefix, suggested vault name). Longer prefixes first.
const PREFIXES: &[(&str, &str)] = &[
    ("github_pat_", "github"),
    ("ghp_", "github"),
    ("gho_", "github"),
    ("ghu_", "github"),
    ("ghs_", "github"),
    ("ghr_", "github"),
    ("glpat-", "gitlab"),
    ("sk-ant-", "anthropic"),
    ("sk-or-", "openrouter"),
    ("sk-proj-", "openai"),
    ("sk_live_", "stripe"),
    ("sk_test_", "stripe-test"),
    ("rk_live_", "stripe"),
    ("xoxb-", "slack"),
    ("xoxp-", "slack"),
    ("xapp-", "slack"),
    ("npm_", "npm"),
    ("AKIA", "aws-access-key-id"),
    ("AIza", "google"),
    ("hf_", "huggingface"),
    ("gsk_", "groq"),
    ("xai-", "xai"),
    ("dop_v1_", "digitalocean"),
];

/// Variable names that usually hold a secret (matched case-insensitively).
const SECRET_WORDS: &[&str] =
    &["TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "APIKEY", "ACCESS_KEY", "PRIVATE_KEY", "AUTH", "CREDENTIAL"];

/// Files worth reading, by name, wherever they turn up.
const FILE_NAMES: &[&str] = &[
    ".npmrc", ".netrc", ".git-credentials", ".pypirc", ".bashrc", ".zshrc", ".profile", ".bash_profile", ".zprofile",
];

/// Credential files inside hidden directories, which the walk skips.
const HOME_FILES: &[&str] =
    &[".aws/credentials", ".config/gh/hosts.yml", ".docker/config.json", ".config/fish/config.fish"];

/// Directories never worth walking into.
const SKIP_DIRS: &[&str] = &["node_modules", "target", "vendor", "dist", "build", "venv", "__pycache__", "Library"];

const MAX_FILE: u64 = 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;

pub struct Finding {
    pub path: PathBuf,
    /// 1-based.
    pub line: usize,
    /// The variable or key it is assigned to, if any.
    pub var: Option<String>,
    pub value: String,
}

impl Finding {
    /// A vault name to suggest: the token's kind when known, else the variable name.
    pub fn suggested_name(&self) -> String {
        if let Some(kind) = kind(&self.value) {
            return kind.to_string();
        }
        let from_var: String = self
            .var
            .as_deref()
            .unwrap_or("secret")
            .to_ascii_lowercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' })
            .take(64)
            .collect();
        if valid_name(&from_var) { from_var } else { "secret".into() }
    }

    /// Enough to recognize the secret, not enough to use it: known prefix and last 4.
    pub fn preview(&self) -> String {
        let prefix = PREFIXES.iter().find(|(p, _)| self.value.starts_with(p)).map_or("", |(p, _)| p);
        let chars: Vec<char> = self.value.chars().collect();
        let tail: String = if chars.len() >= 12 { chars[chars.len() - 4..].iter().collect() } else { String::new() };
        format!("{prefix}…{tail}")
    }
}

fn kind(value: &str) -> Option<&'static str> {
    PREFIXES.iter().find(|(p, _)| value.starts_with(p)).map(|(_, k)| *k)
}

fn secret_var(var: &str) -> bool {
    let up = var.to_ascii_uppercase();
    SECRET_WORDS.iter().any(|w| up.contains(w)) || up.ends_with("_KEY") || up.ends_with("_PAT")
}

/// Rejects empty values, placeholders and references to other variables or commands.
fn real_value(v: &str) -> bool {
    let low = v.to_ascii_lowercase();
    v.len() >= 8
        && !v.contains(char::is_whitespace)
        && !v.starts_with(['$', '<', '{', '%'])
        && !["changeme", "example", "your_", "your-", "xxxx", "placeholder", "redacted", "dummy"]
            .iter()
            .any(|p| low.contains(p))
}

fn unquote(v: &str) -> &str {
    let v = v.trim().trim_end_matches([',', ';']).trim();
    for q in ['"', '\''] {
        if let Some(inner) = v.strip_prefix(q).and_then(|s| s.strip_suffix(q)) {
            return inner;
        }
    }
    // Unquoted: an inline comment ends the value.
    v.split(" #").next().unwrap_or(v).trim()
}

/// Secrets on one line: `NAME=value` style assignments with a secret-looking name, known
/// token shapes anywhere, `password X` (netrc) and `scheme://user:pass@host` URLs.
fn scan_line(line: &str) -> Vec<(Option<String>, String)> {
    let mut out: Vec<(Option<String>, String)> = Vec::new();
    let t = line.trim();
    // Not `//`: .npmrc lines start with it.
    if t.is_empty() || t.starts_with(['#', ';']) {
        return out;
    }
    let body = t.strip_prefix("export ").or_else(|| t.strip_prefix("set -gx ")).unwrap_or(t);

    // Assignment: the first '=' or ':' splits name from value. fish `set -gx NAME value` too.
    let split = body.find(['=', ':']).map(|i| (&body[..i], &body[i + 1..]));
    let split = split.or_else(|| t.starts_with("set -gx ").then(|| body.split_once(' ')).flatten());
    if let Some((var, value)) = split {
        let var = var.trim().trim_matches(['"', '\'']);
        let value = unquote(value);
        let simple = !var.is_empty() && var.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
        if simple && (secret_var(var) || kind(value).is_some()) && real_value(value) {
            out.push((Some(var.to_string()), value.to_string()));
        }
    }

    // Credentials in a URL: scheme://user:secret@host
    if let Some(i) = t.find("://") {
        let rest = &t[i + 3..];
        if let Some((creds, _)) = rest.split_once('@')
            && let Some((_, pass)) = creds.split_once(':')
            && !creds.contains('/')
            && real_value(pass)
        {
            out.push((None, pass.to_string()));
        }
    }

    let words: Vec<&str> = t.split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | '=' | ':' | '@')).collect();
    for (i, w) in words.iter().enumerate() {
        // netrc: `password <secret>`
        if *w == "password"
            && let Some(next) = words.get(i + 1)
            && real_value(next)
        {
            out.push((Some("password".into()), next.to_string()));
        }
        // A known token shape anywhere on the line. Real tokens are key characters with
        // digits in them; `@xai-official/grok` is a package name.
        let token_like = w.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
            && w.chars().any(|c| c.is_ascii_digit());
        if kind(w).is_some() && w.len() >= 16 && token_like && real_value(w) {
            out.push((None, w.to_string()));
        }
    }

    // One report per value.
    let mut seen: Vec<String> = Vec::new();
    out.retain(|(_, v)| {
        let new = !seen.contains(v);
        seen.push(v.clone());
        new
    });
    // Prefer the entry that knows its variable name.
    out.sort_by_key(|(var, _)| var.is_none());
    out
}

/// All secrets found in `text`, as if it were the file at `path`.
pub fn scan_text(path: &Path, text: &str) -> Vec<Finding> {
    let mut found = Vec::new();
    for (i, line) in text.lines().enumerate() {
        for (var, value) in scan_line(line) {
            found.push(Finding { path: path.to_path_buf(), line: i + 1, var, value });
        }
    }
    found
}

/// Reads a small text file; None for anything too big, binary or unreadable.
pub fn read_text(path: &Path) -> Option<String> {
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    if bytes.contains(&0) {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn wanted(name: &str) -> bool {
    let is_env = name == ".env"
        || (name.starts_with(".env.") && !name.ends_with(".example") && !name.ends_with(".sample") && !name.ends_with(".template"));
    is_env || FILE_NAMES.contains(&name)
}

/// Files to scan under `root`: `.env` files and known credential files. Skips hidden
/// directories, dependency and build folders, and symlinks.
pub fn candidate_files(root: &Path, max_depth: usize) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0)];
    let mut entries = 0;
    while let Some((dir, depth)) = stack.pop() {
        let Ok(read) = fs::read_dir(&dir) else { continue };
        for entry in read.flatten() {
            entries += 1;
            if entries > MAX_ENTRIES {
                return files;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                if depth < max_depth && !name.starts_with('.') && !SKIP_DIRS.contains(&name.as_ref()) {
                    stack.push((entry.path(), depth + 1));
                }
            } else if ft.is_file() && wanted(&name) {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    files
}

/// Everything worth scanning in a home directory.
pub fn home_files(home: &Path) -> Vec<PathBuf> {
    let mut files = candidate_files(home, 5);
    for rel in HOME_FILES {
        let p = home.join(rel);
        if p.is_file() {
            files.push(p);
        }
    }
    files
}

/// All findings in these files.
pub fn scan_files(files: &[PathBuf]) -> Vec<Finding> {
    files.iter().filter_map(|p| read_text(p).map(|t| scan_text(p, &t))).flatten().collect()
}

/// The first finding on `line` of `path`, for import.
pub fn finding_at(path: &Path, line: usize) -> io::Result<Finding> {
    let text = read_text(path).ok_or_else(|| io::Error::other(format!("cannot read {}", path.display())))?;
    scan_text(path, &text)
        .into_iter()
        .find(|f| f.line == line)
        .ok_or_else(|| io::Error::other(format!("no secret found on {}:{line}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(line: &str) -> Option<(Option<String>, String)> {
        scan_line(line).into_iter().next()
    }

    const GH: &str = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";

    #[test]
    fn assignments() {
        assert_eq!(one(&format!("GITHUB_TOKEN={GH}")), Some((Some("GITHUB_TOKEN".into()), GH.into())));
        assert_eq!(one(&format!("export GITHUB_TOKEN=\"{GH}\"")).unwrap().1, GH);
        assert_eq!(one("OPENAI_API_KEY='sk-proj-abc123def456ghi'").unwrap().1, "sk-proj-abc123def456ghi");
        assert_eq!(one("DB_PASSWORD=hunter2hunter2 # prod").unwrap().1, "hunter2hunter2");
        assert_eq!(one("//registry.npmjs.org/:_authToken=npm_abcdefghijklmnop1234").unwrap().1, "npm_abcdefghijklmnop1234");
        assert_eq!(one("aws_secret_access_key = wJalrXUtnFEMIK7MDENGbPxRfiCY").unwrap().1, "wJalrXUtnFEMIK7MDENGbPxRfiCY");
        assert_eq!(one("    oauth_token: gho_abcdefghijklmnopqrstuvwxyz0123").unwrap().1, "gho_abcdefghijklmnopqrstuvwxyz0123");
        assert_eq!(one("\"auth\": \"dXNlcjpwYXNzd29yZDEyMw==\",").unwrap().1, "dXNlcjpwYXNzd29yZDEyMw==");
        assert_eq!(one("set -gx ANTHROPIC_API_KEY sk-ant-abcdefghijklmnop").unwrap().1, "sk-ant-abcdefghijklmnop");
    }

    #[test]
    fn other_shapes() {
        assert_eq!(one("machine api.github.com login me password s3cretpassw0rd").unwrap().1, "s3cretpassw0rd");
        assert_eq!(one("https://me:ghp_abcdefghijklmnopqrstuvwxyz@github.com").unwrap().1, "ghp_abcdefghijklmnopqrstuvwxyz");
        assert_eq!(one(&format!("curl -H 'Authorization: token {GH}' x")).unwrap().1, GH);
    }

    #[test]
    fn ignores_non_secrets() {
        for line in [
            "PATH=/usr/bin:/bin",
            "GITHUB_TOKEN=",
            "GITHUB_TOKEN=$(agent-keychain get github)",
            "GITHUB_TOKEN=${GH}",
            "API_KEY=your_api_key_here",
            "API_KEY=changeme",
            "# GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "TOKEN_URL=https://example.com/token",
            "SHORT_KEY=abc",
            "https://github.com/user/repo",
            "NODE_ENV=production",
            "min-release-age-exclude[]=@xai-official/grok*",
            "allow-scripts=@xai-official/grok",
        ] {
            assert!(scan_line(line).is_empty(), "{line}");
        }
    }

    #[test]
    fn one_report_per_value() {
        let found = scan_line(&format!("GITHUB_TOKEN={GH}"));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0.as_deref(), Some("GITHUB_TOKEN"));
    }

    #[test]
    fn names_and_previews() {
        let f = |var: Option<&str>, value: &str| Finding { path: "x".into(), line: 1, var: var.map(Into::into), value: value.into() };
        assert_eq!(f(Some("GITHUB_TOKEN"), GH).suggested_name(), "github");
        assert_eq!(f(Some("DB_PASSWORD"), "hunter2hunter2").suggested_name(), "db_password");
        assert_eq!(f(Some("My Key"), "hunter2hunter2").suggested_name(), "my_key");
        assert_eq!(f(None, "hunter2hunter2").suggested_name(), "secret");
        assert_eq!(f(None, GH).preview(), "ghp_…6789");
        assert_eq!(f(None, "shortpass").preview(), "…");
        assert!(!f(None, GH).preview().contains("abcdefgh"));
    }

    #[test]
    fn picks_files() {
        assert!(wanted(".env") && wanted(".env.local") && wanted(".npmrc"));
        assert!(!wanted(".env.example") && !wanted("env") && !wanted("config.json"));
    }
}
