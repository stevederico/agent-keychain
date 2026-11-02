//! Wire protocol over the Unix socket. One request and one response per connection.
//!
//! Request:  `LIST\n` | `LOG\n` | `VERSION\n` | `GET <name>\n` | `RM <name>\n` | `SET <name>\n<len>\n<bytes>`
//!           | `ALLOW <name>[,<name>...] <seconds>\n`
//!           | `SETMANY <count>\n` then `<count>` times `<name>\n<len>\n<bytes>`
//!           | `RULES\n` | `RULE allow|deny <agent> <secret>\n` | `UNRULE <agent> <secret>\n`
//!           | `GRANTS\n` | `REVOKE <pid>|all\n`
//! Response: `OK <len>\n<bytes>` | `DENIED\n` | `ERR <message>\n`

use crate::crypto::SecretBytes;
use crate::names::valid_name;
use crate::rules::{self, Effect, Rule};
use std::io::{self, BufRead, Read, Write};

pub const MAX_SECRET: usize = 16 * 1024;
const MAX_RESPONSE: usize = 1024 * 1024;
const MAX_LINE: u64 = 256;
/// Longest comma-separated name list in an ALLOW request.
pub const MAX_ALLOW_LIST: usize = 200;
/// Most secrets in one SETMANY.
pub const MAX_BATCH: usize = 32;
/// Longest time an ALLOW grant lasts: 12 hours.
pub const MAX_ALLOW_SECS: u64 = 12 * 3600;

pub enum Request {
    List,
    /// The daemon's version, so a client can spot a stale daemon.
    Version,
    Log,
    Get(String),
    Rm(String),
    Set(String, SecretBytes),
    /// Let the asking process and its descendants `get` these secrets (comma-separated)
    /// without a prompt for this many seconds.
    Allow(String, u64),
    /// Store several secrets under one approval. The String is the names, comma-separated.
    SetMany(String, Vec<(String, SecretBytes)>),
    /// The per-agent rules. Never prompts.
    Rules,
    /// Add or replace the rule for one agent and secret.
    Rule(Rule),
    /// Remove the rule for an agent and secret: (agent, secret).
    Unrule(String, String),
    /// The live ALLOW grants. Never prompts.
    Grants,
    /// End the ALLOW grant held by this pid, or every grant (None). Never prompts:
    /// it only takes access away.
    Revoke(Option<i32>),
}

impl Request {
    pub fn verb(&self) -> &'static str {
        match self {
            Request::List => "LIST",
            Request::Version => "VERSION",
            Request::Log => "LOG",
            Request::Get(_) => "GET",
            Request::Rm(_) => "RM",
            Request::Set(..) | Request::SetMany(..) => "SET",
            Request::Allow(..) => "ALLOW",
            Request::Rules => "RULES",
            Request::Rule(r) if r.effect == Effect::Allow => "RULE-ALLOW",
            Request::Rule(_) => "RULE-DENY",
            Request::Unrule(..) => "RULE-RM",
            Request::Grants => "GRANTS",
            Request::Revoke(_) => "REVOKE",
        }
    }

    /// The name column of the log: the secret names, `agent:secret` for a rule, else `-`.
    pub fn log_name(&self) -> String {
        match self {
            Request::Get(n)
            | Request::Rm(n)
            | Request::Set(n, _)
            | Request::Allow(n, _)
            | Request::SetMany(n, _) => n.clone(),
            Request::Rule(r) => format!("{}:{}", r.agent, r.secret),
            Request::Unrule(a, s) => format!("{a}:{s}"),
            Request::Revoke(Some(pid)) => format!("pid:{pid}"),
            Request::Revoke(None) => "all".into(),
            Request::List | Request::Log | Request::Version | Request::Rules | Request::Grants => "-".into(),
        }
    }
}

pub enum Response {
    Ok(SecretBytes),
    Denied,
    Err(String),
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

fn read_line(r: &mut impl BufRead) -> io::Result<String> {
    let mut buf = Vec::new();
    r.by_ref().take(MAX_LINE).read_until(b'\n', &mut buf)?;
    if buf.pop() != Some(b'\n') {
        return Err(invalid("line too long or connection closed"));
    }
    String::from_utf8(buf).map_err(|_| invalid("line is not utf-8"))
}

fn read_len(r: &mut impl BufRead, min: usize, max: usize) -> io::Result<usize> {
    let n: usize = read_line(r)?.parse().map_err(|_| invalid("bad length"))?;
    if n < min || n > max {
        return Err(invalid("length out of range"));
    }
    Ok(n)
}

fn named(name: Option<&str>) -> io::Result<String> {
    let n = name.ok_or_else(|| invalid("missing secret name"))?;
    if !valid_name(n) {
        return Err(invalid("bad secret name (use a-z, 0-9, '.', '_', '-')"));
    }
    Ok(n.to_string())
}

/// Checks an ALLOW name list: 1 or more valid names, comma-separated, no repeats.
pub fn valid_allow_list(list: &str) -> bool {
    let names: Vec<&str> = list.split(',').collect();
    list.len() <= MAX_ALLOW_LIST
        && names.iter().all(|n| valid_name(n))
        && names.iter().enumerate().all(|(i, n)| !names[..i].contains(n))
}

pub fn read_request(r: &mut impl BufRead) -> io::Result<Request> {
    let line = read_line(r)?;
    let (verb, name) = match line.split_once(' ') {
        Some((v, n)) => (v, Some(n)),
        None => (line.as_str(), None),
    };
    match (verb, name) {
        ("LIST", None) => Ok(Request::List),
        ("LOG", None) => Ok(Request::Log),
        ("VERSION", None) => Ok(Request::Version),
        ("RULES", None) => Ok(Request::Rules),
        ("GRANTS", None) => Ok(Request::Grants),
        ("REVOKE", Some("all")) => Ok(Request::Revoke(None)),
        // Canonical digits only, so "+5" or "05" never reads as pid 5.
        ("REVOKE", Some(text)) => match text.parse::<i32>() {
            Ok(pid) if pid > 1 && pid.to_string() == text => Ok(Request::Revoke(Some(pid))),
            _ => Err(invalid("use REVOKE <pid>|all")),
        },
        ("RULE", Some(rest)) => {
            let [effect, agent, secret] = rest.split(' ').collect::<Vec<_>>()[..] else {
                return Err(invalid("use RULE allow|deny <agent> <secret>"));
            };
            let effect = Effect::parse(effect).ok_or_else(|| invalid("use RULE allow|deny <agent> <secret>"))?;
            Ok(Request::Rule(Rule::new(effect, agent, secret).map_err(|m| invalid(&m))?))
        }
        ("UNRULE", Some(rest)) => {
            let (agent, secret) = rest.split_once(' ').ok_or_else(|| invalid("use UNRULE <agent> <secret>"))?;
            if !rules::valid_agent(agent) || !rules::valid_secret(secret) {
                return Err(invalid("bad agent or secret name"));
            }
            Ok(Request::Unrule(agent.into(), secret.into()))
        }
        ("GET", n) => Ok(Request::Get(named(n)?)),
        ("RM", n) => Ok(Request::Rm(named(n)?)),
        ("ALLOW", Some(rest)) => {
            let (list, secs) = rest.rsplit_once(' ').ok_or_else(|| invalid("missing duration"))?;
            if !valid_allow_list(list) {
                return Err(invalid("bad secret name list"));
            }
            let secs: u64 = secs.parse().map_err(|_| invalid("bad duration"))?;
            if secs == 0 || secs > MAX_ALLOW_SECS {
                return Err(invalid("duration out of range"));
            }
            Ok(Request::Allow(list.to_string(), secs))
        }
        ("SETMANY", Some(count)) => {
            let count: usize = count.parse().map_err(|_| invalid("bad count"))?;
            if count == 0 || count > MAX_BATCH {
                return Err(invalid("count out of range"));
            }
            let mut items: Vec<(String, SecretBytes)> = Vec::with_capacity(count);
            for _ in 0..count {
                let name = named(Some(&read_line(r)?))?;
                if items.iter().any(|(n, _)| *n == name) {
                    return Err(invalid("repeated secret name"));
                }
                let len = read_len(r, 1, MAX_SECRET)?;
                let mut value = SecretBytes::zeroed(len);
                r.read_exact(&mut value)?;
                items.push((name, value));
            }
            let list = items.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(",");
            Ok(Request::SetMany(list, items))
        }
        ("SET", n) => {
            let name = named(n)?;
            let len = read_len(r, 1, MAX_SECRET)?;
            let mut value = SecretBytes::zeroed(len);
            r.read_exact(&mut value)?;
            Ok(Request::Set(name, value))
        }
        _ => Err(invalid("unknown request")),
    }
}

pub fn write_request(w: &mut impl Write, req: &Request) -> io::Result<()> {
    match req {
        Request::List => w.write_all(b"LIST\n")?,
        Request::Log => w.write_all(b"LOG\n")?,
        Request::Version => w.write_all(b"VERSION\n")?,
        Request::Rules => w.write_all(b"RULES\n")?,
        Request::Grants => w.write_all(b"GRANTS\n")?,
        Request::Revoke(Some(pid)) => writeln!(w, "REVOKE {pid}")?,
        Request::Revoke(None) => w.write_all(b"REVOKE all\n")?,
        Request::Rule(r) => writeln!(w, "RULE {} {} {}", r.effect.as_str(), r.agent, r.secret)?,
        Request::Unrule(a, s) => writeln!(w, "UNRULE {a} {s}")?,
        Request::Get(n) => writeln!(w, "GET {n}")?,
        Request::Rm(n) => writeln!(w, "RM {n}")?,
        Request::Allow(list, secs) => writeln!(w, "ALLOW {list} {secs}")?,
        Request::SetMany(_, items) => {
            writeln!(w, "SETMANY {}", items.len())?;
            for (n, v) in items {
                write!(w, "{n}\n{}\n", v.len())?;
                w.write_all(v)?;
            }
        }
        Request::Set(n, v) => {
            write!(w, "SET {n}\n{}\n", v.len())?;
            w.write_all(v)?;
        }
    }
    w.flush()
}

pub fn write_ok(w: &mut impl Write, data: &[u8]) -> io::Result<()> {
    writeln!(w, "OK {}", data.len())?;
    w.write_all(data)?;
    w.flush()
}

pub fn write_denied(w: &mut impl Write) -> io::Result<()> {
    w.write_all(b"DENIED\n")?;
    w.flush()
}

pub fn write_err(w: &mut impl Write, msg: &str) -> io::Result<()> {
    let msg: String = msg.chars().map(|c| if c.is_control() { ' ' } else { c }).take(200).collect();
    writeln!(w, "ERR {msg}")?;
    w.flush()
}

pub fn read_response(r: &mut impl BufRead) -> io::Result<Response> {
    let line = read_line(r)?;
    if line == "DENIED" {
        return Ok(Response::Denied);
    }
    if let Some(msg) = line.strip_prefix("ERR ") {
        return Ok(Response::Err(msg.to_string()));
    }
    let Some(len) = line.strip_prefix("OK ") else { return Err(invalid("bad response")) };
    let len: usize = len.parse().map_err(|_| invalid("bad length"))?;
    if len > MAX_RESPONSE {
        return Err(invalid("response too large"));
    }
    let mut data = SecretBytes::zeroed(len);
    r.read_exact(&mut data)?;
    Ok(Response::Ok(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(req: Request) -> Request {
        let mut buf = Vec::new();
        write_request(&mut buf, &req).unwrap();
        read_request(&mut &buf[..]).unwrap()
    }

    #[test]
    fn requests_roundtrip() {
        assert!(matches!(roundtrip(Request::List), Request::List));
        assert!(matches!(roundtrip(Request::Version), Request::Version));
        assert!(matches!(roundtrip(Request::Get("github".into())), Request::Get(n) if n == "github"));
        match roundtrip(Request::Set("github".into(), SecretBytes::from_slice(b"a\nb"))) {
            Request::Set(n, v) => assert_eq!((n.as_str(), &v[..]), ("github", &b"a\nb"[..])),
            _ => panic!(),
        }
        let items = vec![("a".into(), SecretBytes::from_slice(b"1")), ("b".into(), SecretBytes::from_slice(b"22"))];
        match roundtrip(Request::SetMany("a,b".into(), items)) {
            Request::SetMany(l, items) => {
                assert_eq!(l, "a,b");
                assert_eq!(&items[1].1[..], b"22");
            }
            _ => panic!(),
        }
        assert!(matches!(roundtrip(Request::Allow("github,aws.prod".into(), 3600)),
            Request::Allow(l, 3600) if l == "github,aws.prod"));
        assert!(matches!(roundtrip(Request::Rules), Request::Rules));
        let rule = Rule::new(Effect::Deny, "codex", "*").unwrap();
        assert!(matches!(roundtrip(Request::Rule(rule.clone())), Request::Rule(r) if r == rule));
        assert!(matches!(roundtrip(Request::Unrule("claude".into(), "github".into())),
            Request::Unrule(a, s) if a == "claude" && s == "github"));
        assert!(matches!(roundtrip(Request::Grants), Request::Grants));
        assert!(matches!(roundtrip(Request::Revoke(Some(4242))), Request::Revoke(Some(4242))));
        assert!(matches!(roundtrip(Request::Revoke(None)), Request::Revoke(None)));
    }

    #[test]
    fn rejects_bad_requests() {
        for raw in [&b"GET ../etc\n"[..], b"GET\n", b"LIST x\n", b"NOPE\n", b"SET github\n0\n", b"GET github"] {
            assert!(read_request(&mut &raw[..]).is_err(), "{raw:?}");
        }
        for raw in ["ALLOW github\n", "ALLOW github 0\n", "ALLOW github 43201\n", "ALLOW github,github 60\n",
            "ALLOW github, 60\n", "ALLOW ,github 60\n", "ALLOW Git 60\n", "ALLOW github -5\n",
            "SETMANY 0\n", "SETMANY 33\n", "SETMANY 2\na\n1\nxa\n1\ny", "SETMANY 1\nBad\n1\nx",
            "RULES x\n", "RULE allow claude\n", "RULE allow claude *\n", "RULE permit claude github\n",
            "RULE allow agent-keychain github\n", "RULE allow claude  github\n", "RULE deny a/b github\n",
            "UNRULE claude\n", "UNRULE claude Bad\n", "UNRULE claude github x\n",
            "GRANTS x\n", "REVOKE\n", "REVOKE 1\n", "REVOKE 0\n", "REVOKE -5\n", "REVOKE +5\n", "REVOKE 05\n",
            "REVOKE All\n", "REVOKE 5 6\n"] {
            assert!(read_request(&mut raw.as_bytes()).is_err(), "{raw:?}");
        }
        let long = format!("GET {}\n", "a".repeat(400));
        assert!(read_request(&mut long.as_bytes()).is_err());
    }

    #[test]
    fn responses() {
        let mut buf = Vec::new();
        write_ok(&mut buf, b"tok").unwrap();
        write_denied(&mut buf).unwrap();
        write_err(&mut buf, "bad\nthing").unwrap();
        let mut r = &buf[..];
        assert!(matches!(read_response(&mut r).unwrap(), Response::Ok(v) if &v[..] == b"tok"));
        assert!(matches!(read_response(&mut r).unwrap(), Response::Denied));
        assert!(matches!(read_response(&mut r).unwrap(), Response::Err(m) if m == "bad thing"));
    }
}
