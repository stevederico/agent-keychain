//! Per-agent rules: `allow claude github` lets a program named `claude` get `github`
//! without a prompt; `deny codex *` refuses `codex` everything, also without a prompt.
//!
//! File format, one rule per line, `#` starts a comment:
//!
//! ```text
//! allow claude github
//! deny codex *
//! ```
//!
//! An agent is a process name as the kernel reports it in `/proc/<pid>/comm` (at most
//! 15 bytes). Processes choose their own names, so `allow` trusts the name; `deny` can
//! only take prompts away from a request, never add access.

use crate::names::valid_name;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

/// Longest process name the kernel keeps (TASK_COMM_LEN - 1).
pub const MAX_AGENT: usize = 15;
/// Most rules in the file.
pub const MAX_RULES: usize = 256;
/// The client's own name. It is skipped when judging a chain, so it cannot be a rule agent.
pub const CLIENT_NAME: &str = "agent-keychain";
/// Every secret, in a deny rule.
pub const ALL: &str = "*";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
}

impl Effect {
    pub fn as_str(self) -> &'static str {
        match self {
            Effect::Allow => "allow",
            Effect::Deny => "deny",
        }
    }

    pub fn parse(s: &str) -> Option<Effect> {
        match s {
            "allow" => Some(Effect::Allow),
            "deny" => Some(Effect::Deny),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub effect: Effect,
    pub agent: String,
    pub secret: String,
}

impl Rule {
    /// Checks names and the one combination refused: `allow <agent> *`.
    pub fn new(effect: Effect, agent: &str, secret: &str) -> Result<Rule, String> {
        if !valid_agent(agent) {
            return Err(format!("bad agent name {agent:?}: use 1 to 15 of A-Z, a-z, 0-9, '.', '_', '-'"));
        }
        if !valid_secret(secret) {
            return Err(format!("bad secret name {secret:?}: use a secret name, or * for all"));
        }
        if effect == Effect::Allow && secret == ALL {
            return Err("allow needs one secret name; * is only for deny".into());
        }
        Ok(Rule { effect, agent: agent.into(), secret: secret.into() })
    }

    fn covers(&self, secret: &str) -> bool {
        self.secret == ALL || self.secret == secret
    }
}

/// Agent names: 1 to 15 of `A-Z a-z 0-9 . _ -`, and not the client's own name.
pub fn valid_agent(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_AGENT
        && s != CLIENT_NAME
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A secret name, or `*` for all of them.
pub fn valid_secret(s: &str) -> bool {
    s == ALL || valid_name(s)
}

/// What the rules say about one request.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// No prompt; the agent named is the one whose allow rule matched.
    Allow(String),
    /// Refused without a prompt; the agent named is the one whose deny rule matched.
    Deny(String),
    /// No rule decides: prompt as usual.
    Ask,
}

/// Judges a request for `secret` from a process chain, nearest first (the client itself
/// already left out). Deny wins: a deny rule for any process in the chain refuses.
/// Otherwise the agent is the nearest process named in any rule, and only its own allow
/// rule for this secret skips the prompt. So `codex` started by `claude` is judged as
/// `codex`, and does not inherit what `claude` is allowed.
pub fn decide(rules: &[Rule], chain: &[String], secret: &str) -> Decision {
    let deny = chain.iter().find(|name| {
        rules.iter().any(|r| r.effect == Effect::Deny && r.agent == **name && r.covers(secret))
    });
    if let Some(name) = deny {
        return Decision::Deny(name.clone());
    }
    let Some(agent) = chain.iter().find(|name| rules.iter().any(|r| r.agent == **name)) else {
        return Decision::Ask;
    };
    if rules.iter().any(|r| r.effect == Effect::Allow && r.agent == *agent && r.covers(secret)) {
        Decision::Allow(agent.clone())
    } else {
        Decision::Ask
    }
}

/// The first process in the chain that may not change rules: one named `agent` (the agent
/// the change is about), or one that already has a rule. Stops an agent asking to allow itself.
pub fn blocks_change<'a>(rules: &[Rule], chain: &'a [String], agent: Option<&str>) -> Option<&'a str> {
    chain
        .iter()
        .find(|name| Some(name.as_str()) == agent || rules.iter().any(|r| r.agent == **name))
        .map(String::as_str)
}

/// Parses the rules file. Blank lines and `#` comments are skipped; anything else that
/// is not a valid rule is an error naming its line.
pub fn parse(text: &str) -> Result<Vec<Rule>, String> {
    let mut rules: Vec<Rule> = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.split_once('#').map_or(line, |(l, _)| l).trim();
        if line.is_empty() {
            continue;
        }
        let err = |m: &str| format!("line {}: {m}", i + 1);
        let words: Vec<&str> = line.split_whitespace().collect();
        let [effect, agent, secret] = words[..] else { return Err(err("use: allow|deny <agent> <secret>")) };
        let effect = Effect::parse(effect).ok_or_else(|| err("use: allow|deny <agent> <secret>"))?;
        let rule = Rule::new(effect, agent, secret).map_err(|m| err(&m))?;
        if rules.iter().any(|r| r.agent == rule.agent && r.secret == rule.secret) {
            return Err(err("a rule for this agent and secret is already above"));
        }
        rules.push(rule);
    }
    if rules.len() > MAX_RULES {
        return Err(format!("more than {MAX_RULES} rules"));
    }
    Ok(rules)
}

/// One rule per line, no comments: the RULES response and the file body.
pub fn format(rules: &[Rule]) -> String {
    rules.iter().map(|r| format!("{} {} {}\n", r.effect.as_str(), r.agent, r.secret)).collect()
}

const HEADER: &str = "# agent-keychain rules, owned by agent-keychaind. Change them with
# agent-keychain allow|deny|unallow <agent> <secret>; each change asks for your password.
";

/// The rules file, kept by the daemon.
pub struct Rules {
    path: PathBuf,
    list: Vec<Rule>,
}

impl Rules {
    /// Loads the rules at `path` (none if missing).
    pub fn open(path: PathBuf) -> io::Result<Rules> {
        let list = match fs::read_to_string(&path) {
            Ok(text) => parse(&text).map_err(|m| io::Error::new(io::ErrorKind::InvalidData, m))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        Ok(Rules { path, list })
    }

    pub fn list(&self) -> &[Rule] {
        &self.list
    }

    pub fn has(&self, rule: &Rule) -> bool {
        self.list.contains(rule)
    }

    /// Adds a rule, replacing any rule for the same agent and secret.
    pub fn put(&mut self, rule: Rule) -> io::Result<()> {
        let mut next = self.list.clone();
        let full = next.len() >= MAX_RULES;
        match next.iter_mut().find(|r| r.agent == rule.agent && r.secret == rule.secret) {
            Some(r) => *r = rule,
            None if full => return Err(io::Error::other(format!("at most {MAX_RULES} rules"))),
            None => next.push(rule),
        }
        self.replace(next)
    }

    /// Removes the rule for this agent and secret. False when there was none.
    pub fn remove(&mut self, agent: &str, secret: &str) -> io::Result<bool> {
        let next: Vec<Rule> = self.list.iter().filter(|r| !(r.agent == agent && r.secret == secret)).cloned().collect();
        if next.len() == self.list.len() {
            return Ok(false);
        }
        self.replace(next)?;
        Ok(true)
    }

    /// Saves, then swaps in the new list; on error the old list stays.
    fn replace(&mut self, next: Vec<Rule>) -> io::Result<()> {
        save(&self.path, &next)?;
        self.list = next;
        Ok(())
    }
}

/// Writes a temp file (0600), fsyncs it, renames it over the rules, then fsyncs the directory.
fn save(path: &PathBuf, rules: &[Rule]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(HEADER.as_bytes())?;
        f.write_all(format(rules).as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn rules(text: &str) -> Vec<Rule> {
        parse(text).unwrap()
    }

    fn chain(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_and_formats() {
        let r = rules("# comment\n\nallow claude github  # trailing\ndeny codex *\n  allow my.agent_1 aws.prod\n");
        assert_eq!(r.len(), 3);
        assert_eq!(r[1], Rule { effect: Effect::Deny, agent: "codex".into(), secret: "*".into() });
        assert_eq!(format(&r), "allow claude github\ndeny codex *\nallow my.agent_1 aws.prod\n");
        assert_eq!(parse(&format(&r)).unwrap(), r, "round trip");
        assert_eq!(parse("").unwrap(), vec![]);
    }

    #[test]
    fn rejects_bad_rules() {
        for bad in ["allow claude", "allow claude github extra", "permit claude github", "allow claude GitHub",
            "allow claude ../x", "allow claude *", "allow agent-keychain github", "allow a/b github",
            "allow abcdefghijklmnop github", "allow claude github\ndeny claude github", "deny * github"] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        assert!(parse("allow claude github\nnope").unwrap_err().starts_with("line 2:"));
        let many: String = (0..=MAX_RULES).map(|i| format!("allow a{i} github\n")).collect();
        assert!(parse(&many).is_err());
    }

    #[test]
    fn agent_names() {
        for ok in ["claude", "codex", "Claude-Code", "a", "node.js", "abcdefghijklmno"] {
            assert!(valid_agent(ok), "{ok}");
        }
        for bad in ["", "a b", "abcdefghijklmnop", "agent-keychain", "x*", "é"] {
            assert!(!valid_agent(bad), "{bad:?}");
        }
    }

    #[test]
    fn no_rule_asks() {
        assert_eq!(decide(&[], &chain(&["zsh", "claude"]), "github"), Decision::Ask);
        let r = rules("allow claude github");
        assert_eq!(decide(&r, &chain(&["zsh", "bash"]), "github"), Decision::Ask, "no agent with a rule");
        assert_eq!(decide(&r, &chain(&["zsh", "claude"]), "stripe"), Decision::Ask, "agent has no rule for it");
    }

    #[test]
    fn allow_matches_exact_names() {
        let r = rules("allow claude github");
        assert_eq!(decide(&r, &chain(&["zsh", "claude", "ghostty"]), "github"), Decision::Allow("claude".into()));
        assert_eq!(decide(&r, &chain(&["claude-x"]), "github"), Decision::Ask);
        assert_eq!(decide(&r, &chain(&["Claude"]), "github"), Decision::Ask);
    }

    #[test]
    fn deny_wins() {
        let r = rules("allow claude github\ndeny codex github");
        // Anywhere in the chain, nearer or farther than the allowed agent.
        assert_eq!(decide(&r, &chain(&["codex", "claude"]), "github"), Decision::Deny("codex".into()));
        assert_eq!(decide(&r, &chain(&["claude", "codex"]), "github"), Decision::Deny("codex".into()));
        // The same agent: deny * beats its own allow.
        let r = rules("allow claude github\ndeny claude *");
        assert_eq!(decide(&r, &chain(&["claude"]), "github"), Decision::Deny("claude".into()));
    }

    #[test]
    fn star_denies_everything() {
        let r = rules("deny codex *");
        for s in ["github", "stripe", "aws.prod"] {
            assert_eq!(decide(&r, &chain(&["sh", "codex"]), s), Decision::Deny("codex".into()));
        }
        assert_eq!(decide(&r, &chain(&["sh", "claude"]), "github"), Decision::Ask);
    }

    #[test]
    fn nearest_agent_is_judged() {
        // codex under claude is codex: it does not inherit claude's allow.
        let r = rules("allow claude github\nallow codex stripe");
        assert_eq!(decide(&r, &chain(&["sh", "codex", "zsh", "claude"]), "github"), Decision::Ask);
        assert_eq!(decide(&r, &chain(&["sh", "codex", "zsh", "claude"]), "stripe"), Decision::Allow("codex".into()));
        // A process with no rule in between is passed over.
        assert_eq!(decide(&r, &chain(&["sh", "bash", "claude"]), "github"), Decision::Allow("claude".into()));
    }

    #[test]
    fn rule_changes_blocked_from_inside_agents() {
        let r = rules("allow claude github");
        let c = chain(&["zsh", "ghostty"]);
        assert_eq!(blocks_change(&r, &c, Some("codex")), None);
        assert_eq!(blocks_change(&r, &chain(&["zsh", "codex"]), Some("codex")), Some("codex"), "allowing itself");
        assert_eq!(blocks_change(&r, &chain(&["zsh", "claude"]), Some("codex")), Some("claude"), "has a rule");
        assert_eq!(blocks_change(&[], &chain(&["zsh", "claude"]), None), None);
    }

    #[test]
    fn file_is_private_and_atomic() {
        let dir = std::env::temp_dir().join(format!("akc-rules-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rules");
        let mut r = Rules::open(path.clone()).unwrap();
        assert!(r.list().is_empty() && !path.exists());
        r.put(Rule::new(Effect::Allow, "claude", "github").unwrap()).unwrap();
        r.put(Rule::new(Effect::Deny, "claude", "github").unwrap()).unwrap();
        assert_eq!(r.list().len(), 1, "one rule per agent and secret");
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(!dir.join("rules.tmp").exists());
        let again = Rules::open(path.clone()).unwrap();
        assert_eq!(again.list(), r.list());
        assert!(r.remove("claude", "github").unwrap());
        assert!(!r.remove("claude", "github").unwrap());
        assert!(Rules::open(path).unwrap().list().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }
}
