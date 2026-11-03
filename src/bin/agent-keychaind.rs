//! agent-keychaind: holds the vault and hands out secrets after polkit approval.
//! Runs as the `agent-keychain` system user (see dist/agent-keychaind.service).

use agent_keychain::crypto::{Key, SecretBytes, random};
use agent_keychain::peer::{self, Peer};
use agent_keychain::proto::{self, Request};
use agent_keychain::rules::{self, Decision, Effect, Rules};
use agent_keychain::vault::Vault;
use agent_keychain::{sys, time};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::collections::HashMap;
use std::os::fd::{AsRawFd, RawFd};
use std::os::raw::c_ulong;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram, UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_SOCKET: &str = "/run/agent-keychain/sock";
const DEFAULT_STATE: &str = "/var/lib/agent-keychain";
const CREDENTIAL_NAME: &str = "vault-key";
const PKCHECK: &str = "/usr/bin/pkcheck";
const ACTION_READ: &str = "dev.agent-keychain.read";
const ACTION_WRITE: &str = "dev.agent-keychain.write";
const ACTION_ALLOW: &str = "dev.agent-keychain.allow";
const ACTION_RULE: &str = "dev.agent-keychain.rule";
const LOG_TAIL: usize = 50;
/// The log rotates to `log.1` at this size, so it never holds more than about twice it.
const DEFAULT_LOG_MAX: u64 = 1 << 20;
/// Other users' refused connections are logged at most this often, so they cannot
/// fill the disk or push the owner's entries out of the log.
const FOREIGN_LOG_GAP: Duration = Duration::from_secs(60);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_BACKOFF_SECS: u64 = 30;
const MAX_BACKOFF: Duration = Duration::from_secs(600);

const USAGE: &str = "usage: agent-keychaind [--owner-uid UID] [--socket PATH] [--state-dir DIR]
                      [--key-file PATH] [--approver PROGRAM] [--deny-backoff SECS]
                      [--log-max BYTES]
       agent-keychaind --gen-key   (print 32 random bytes, for systemd-creds)
       agent-keychaind --version

The owner uid may also come from AGENT_KEYCHAIN_OWNER_UID. Without --key-file the
vault key is read from the systemd credential \"vault-key\".

After a denial, no prompt is shown for --deny-backoff seconds (default 30),
doubling with each denial in a row, up to 10 minutes.

The log moves to log.1 once it reaches --log-max bytes (default 1 MiB).";

struct Config {
    socket: PathBuf,
    state_dir: PathBuf,
    key_file: Option<PathBuf>,
    owner_uid: u32,
    /// Test hook: a program run as `PROGRAM <action> <name> <caller> [key=value...]`,
    /// the trailing pairs being the details polkit would get. Exit codes as
    /// pkcheck: 0 approves, 1 or 3 denies, anything else is an error.
    /// Without it, approval goes through polkit.
    approver: Option<PathBuf>,
    deny_backoff: Duration,
    log_max: u64,
}

enum Mode {
    GenKey,
    Run(Config),
}

fn parse_args() -> Result<Mode, String> {
    let mut args = env::args().skip(1);
    let mut socket = PathBuf::from(DEFAULT_SOCKET);
    let mut state_dir = PathBuf::from(DEFAULT_STATE);
    let mut key_file = None;
    let mut approver = None;
    let mut owner = env::var("AGENT_KEYCHAIN_OWNER_UID").ok();
    let mut backoff = DEFAULT_BACKOFF_SECS.to_string();
    let mut log_max = DEFAULT_LOG_MAX.to_string();

    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{arg} needs a value\n\n{USAGE}"));
        match arg.as_str() {
            "--gen-key" => return Ok(Mode::GenKey),
            "-V" | "--version" => {
                println!("agent-keychaind {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--socket" => socket = value()?.into(),
            "--state-dir" => state_dir = value()?.into(),
            "--key-file" => key_file = Some(value()?.into()),
            "--approver" => approver = Some(value()?.into()),
            "--owner-uid" => owner = Some(value()?),
            "--deny-backoff" => backoff = value()?,
            "--log-max" => log_max = value()?,
            "-h" | "--help" => return Err(USAGE.into()),
            _ => return Err(format!("unknown argument {arg}\n\n{USAGE}")),
        }
    }
    let owner = owner.ok_or_else(|| format!("no owner uid\n\n{USAGE}"))?;
    let owner_uid = owner.parse().map_err(|_| format!("bad owner uid {owner:?}"))?;
    let backoff = backoff.parse().map_err(|_| format!("bad --deny-backoff {backoff:?}"))?;
    let deny_backoff = Duration::from_secs(backoff);
    let log_max = log_max.parse().map_err(|_| format!("bad --log-max {log_max:?}"))?;
    Ok(Mode::Run(Config { socket, state_dir, key_file, owner_uid, approver, deny_backoff, log_max }))
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("agent-keychaind: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let cfg = match parse_args()? {
        Mode::GenKey => {
            let mut key = SecretBytes::zeroed(32);
            random(&mut key).map_err(|e| format!("getrandom: {e}"))?;
            return io::stdout().write_all(&key).map_err(|e| e.to_string());
        }
        Mode::Run(cfg) => cfg,
    };

    // No core dumps, and other processes of our uid cannot ptrace us.
    // SAFETY: prctl(PR_SET_DUMPABLE, 0) has no pointer arguments.
    unsafe { sys::prctl(sys::PR_SET_DUMPABLE, 0 as c_ulong) };

    let key = load_key(&cfg)?;
    fs::create_dir_all(&cfg.state_dir).map_err(|e| format!("{}: {e}", cfg.state_dir.display()))?;
    let vault = Vault::open(cfg.state_dir.join("vault"), key).map_err(|e| format!("vault: {e}"))?;
    let rules = Rules::open(cfg.state_dir.join("rules")).map_err(|e| format!("rules: {e}"))?;
    let log = open_log(&cfg.state_dir).map_err(|e| format!("log: {e}"))?;

    let _ = fs::remove_file(&cfg.socket);
    let listener = UnixListener::bind(&cfg.socket).map_err(|e| format!("{}: {e}", cfg.socket.display()))?;
    // Anyone may connect; only the owner uid is served, and every secret needs approval.
    fs::set_permissions(&cfg.socket, fs::Permissions::from_mode(0o666))
        .map_err(|e| format!("{}: {e}", cfg.socket.display()))?;
    eprintln!("agent-keychaind: serving uid {} on {}", cfg.owner_uid, cfg.socket.display());
    notify_ready();

    let shared = Arc::new(Shared {
        cfg,
        vault: Mutex::new(vault),
        log: Mutex::new(log),
        foreign_logged: Mutex::new(None),
        prompt: Mutex::new(()),
        backoff: Mutex::new(Backoff::default()),
        grants: Mutex::new(HashMap::new()),
        rules: Mutex::new(rules),
    });
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let shared = Arc::clone(&shared);
                thread::spawn(move || {
                    if let Err(e) = serve(&shared, &stream) {
                        eprintln!("agent-keychaind: connection: {e}");
                    }
                });
            }
            Err(e) => eprintln!("agent-keychaind: accept: {e}"),
        }
    }
    Ok(())
}

/// Tells systemd the socket is up (Type=notify), so `systemctl start` returns only once
/// clients can connect. Does nothing outside systemd.
fn notify_ready() {
    let Some(path) = env::var_os("NOTIFY_SOCKET") else { return };
    let sent = UnixDatagram::unbound().and_then(|sock| match path.as_bytes().strip_prefix(b"@") {
        Some(name) => sock.send_to_addr(b"READY=1", &SocketAddr::from_abstract_name(name)?),
        None => sock.send_to(b"READY=1", &path),
    });
    if let Err(e) = sent {
        eprintln!("agent-keychaind: notify systemd: {e}");
    }
}

fn load_key(cfg: &Config) -> Result<Key, String> {
    let path = match &cfg.key_file {
        Some(p) => p.clone(),
        None => {
            let dir = env::var_os("CREDENTIALS_DIRECTORY")
                .ok_or("no --key-file and no systemd credentials (CREDENTIALS_DIRECTORY unset)")?;
            PathBuf::from(dir).join(CREDENTIAL_NAME)
        }
    };
    let bytes = SecretBytes::from_vec(fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?);
    Key::from_bytes(&bytes).map_err(|e| e.to_string())
}

struct Shared {
    cfg: Config,
    vault: Mutex<Vault>,
    log: Mutex<File>,
    /// When another user's refused connection was last logged.
    foreign_logged: Mutex<Option<Instant>>,
    /// Held while a prompt is open. One at a time, so prompts never stack up and the
    /// user is not left guessing which request a prompt belongs to.
    prompt: Mutex<()>,
    backoff: Mutex<Backoff>,
    /// ALLOW grants, keyed by the granted process's (pid, start time).
    grants: Mutex<HashMap<(i32, u64), Grant>>,
    /// Per-agent allow and deny rules, saved in `<state-dir>/rules`.
    rules: Mutex<Rules>,
}

/// Secrets a process and its descendants may `get` without a prompt, until a deadline.
struct Grant {
    names: Vec<String>,
    until: Instant,
}

/// After a denial, no prompts for a while, doubling with each denial in a row, so an
/// agent cannot wear the user down by asking again and again.
#[derive(Default)]
struct Backoff {
    until: Option<Instant>,
    streak: u32,
}

impl Backoff {
    fn remaining(&self) -> Option<Duration> {
        self.until?.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())
    }

    fn denied(&mut self, base: Duration) {
        let wait = base.saturating_mul(1 << self.streak.min(5)).min(MAX_BACKOFF);
        self.streak += 1;
        self.until = Some(Instant::now() + wait);
    }

    fn approved(&mut self) {
        *self = Backoff::default();
    }
}

/// A panic in one connection must not take the vault down with it.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn serve(sh: &Shared, stream: &UnixStream) -> io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut w = stream;
    let peer = peer::peer_cred(stream.as_raw_fd())?;
    let caller = peer::describe_caller(peer.pid);
    if peer.uid != sh.cfg.owner_uid {
        let mut last = lock(&sh.foreign_logged);
        if last.is_none_or(|t| t.elapsed() >= FOREIGN_LOG_GAP) {
            *last = Some(Instant::now());
            drop(last);
            record(sh, "CONNECT", "-", &peer, &caller, "refused");
        }
        return proto::write_err(&mut w, "this keychain belongs to another user");
    }

    let req = match proto::read_request(&mut BufReader::new(stream)) {
        Ok(r) => r,
        Err(e) => {
            record(sh, "BAD", "-", &peer, &caller, "malformed");
            return proto::write_err(&mut w, &e.to_string());
        }
    };
    // Log even when the reply could not be sent: the outcome happened either way.
    let (outcome, sent) = respond(sh, &req, &peer, &caller, stream.as_raw_fd(), &mut w);
    record(sh, req.verb(), &req.log_name(), &peer, &caller, outcome);
    sent
}

/// The outcome to log, and whether the reply reached the client.
type Reply = (&'static str, io::Result<()>);

fn respond(sh: &Shared, req: &Request, peer: &Peer, caller: &str, sock: RawFd, w: &mut impl Write) -> Reply {
    match req {
        Request::List => {
            let names = lock(&sh.vault).names().collect::<Vec<_>>().join("\n");
            ("listed", proto::write_ok(w, names.as_bytes()))
        }
        Request::Log => ("shown", proto::write_ok(w, &log_tail(&sh.cfg.state_dir))),
        Request::Version => ("shown", proto::write_ok(w, env!("CARGO_PKG_VERSION").as_bytes())),
        Request::Get(name) => {
            if !lock(&sh.vault).contains(name) {
                return missing(w, name);
            }
            // A deny rule refuses without a prompt, and without starting the backoff:
            // nobody was asked, so nobody was worn down.
            let decision = rule_decision(sh, sock, peer.pid, name);
            if let Decision::Deny(_) = decision {
                return ("denied-by-rule", proto::write_denied(w));
            }
            let outcome = if let Decision::Allow(_) = decision {
                "allowed-by-rule"
            } else if granted(sh, sock, peer.pid, name) {
                "allowed-by-grant"
            } else if let Some(refused) = gate(sh, ACTION_READ, name, &[], caller, peer, w) {
                return refused;
            } else {
                "allowed"
            };
            // Read after approval: the value may have changed while the prompt was up.
            let value = lock(&sh.vault).get(name);
            match value {
                Ok(Some(v)) => (outcome, proto::write_ok(w, &v)),
                Ok(None) => missing(w, name),
                Err(e) => ("error", proto::write_err(w, &format!("cannot open {name}: {e}"))),
            }
        }
        Request::Set(name, value) => {
            if let Some(refused) = gate(sh, ACTION_WRITE, name, &[], caller, peer, w) {
                return refused;
            }
            let saved = lock(&sh.vault).set(name, value);
            match saved {
                Ok(()) => ("stored", proto::write_ok(w, b"")),
                Err(e) => ("error", proto::write_err(w, &format!("cannot save: {e}"))),
            }
        }
        Request::Rm(name) => {
            if !lock(&sh.vault).contains(name) {
                return missing(w, name);
            }
            if let Some(refused) = gate(sh, ACTION_WRITE, name, &[], caller, peer, w) {
                return refused;
            }
            let removed = lock(&sh.vault).remove(name);
            match removed {
                Ok(true) => ("removed", proto::write_ok(w, b"")),
                // Removed by another request while the prompt was up.
                Ok(false) => missing(w, name),
                Err(e) => ("error", proto::write_err(w, &format!("cannot save: {e}"))),
            }
        }
        Request::SetMany(list, items) => {
            if let Some(refused) = gate(sh, ACTION_WRITE, list, &[], caller, peer, w) {
                return refused;
            }
            let pairs: Vec<(&str, &[u8])> = items.iter().map(|(n, v)| (n.as_str(), &v[..])).collect();
            let saved = lock(&sh.vault).set_many(&pairs);
            match saved {
                Ok(()) => ("stored", proto::write_ok(w, b"")),
                Err(e) => ("error", proto::write_err(w, &format!("cannot save: {e}"))),
            }
        }
        Request::Allow(list, secs) => {
            let absent = {
                let vault = lock(&sh.vault);
                list.split(',').find(|n| !vault.contains(n)).map(str::to_string)
            };
            if let Some(name) = absent {
                return missing(w, &name);
            }
            let Some(chain) = verified_ancestry(sock, peer.pid) else {
                return ("error", proto::write_err(w, "cannot identify the asking process"));
            };
            let details = [("duration", duration(*secs))];
            if let Some(refused) = gate(sh, ACTION_ALLOW, list, &details, caller, peer, w) {
                return refused;
            }
            let names = list.split(',').map(str::to_string).collect();
            let until = Instant::now() + Duration::from_secs(*secs);
            lock(&sh.grants).insert(chain[0], Grant { names, until });
            ("approved", proto::write_ok(w, b""))
        }
        Request::Grants => ("listed", proto::write_ok(w, grants_text(sh).as_bytes())),
        Request::Revoke(pid) => {
            let mut grants = lock(&sh.grants);
            let before = grants.len();
            grants.retain(|&(p, _), _| pid.is_some_and(|want| p != want));
            let revoked = before - grants.len();
            drop(grants);
            match (pid, revoked) {
                (Some(pid), 0) => ("missing", proto::write_err(w, &format!("no grant held by pid {pid}"))),
                _ => ("revoked", proto::write_ok(w, revoked.to_string().as_bytes())),
            }
        }
        Request::Rules => {
            let text = rules::format(lock(&sh.rules).list());
            ("listed", proto::write_ok(w, text.trim_end().as_bytes()))
        }
        Request::Rule(rule) => {
            if lock(&sh.rules).has(rule) {
                return ("unchanged", proto::write_ok(w, b""));
            }
            let (agent, secret) = (&rule.agent, &rule.secret);
            let change = match (rule.effect, secret.as_str()) {
                (Effect::Allow, _) => format!("allow \"{agent}\" to get \"{secret}\" without asking"),
                (Effect::Deny, rules::ALL) => format!("refuse \"{agent}\" every secret without asking"),
                (Effect::Deny, _) => format!("refuse \"{agent}\" the secret \"{secret}\" without asking"),
            };
            change_rules(sh, req, agent, change, caller, peer, sock, w, |r| r.put(rule.clone()).map(|()| true))
        }
        Request::Unrule(agent, secret) => {
            let found = lock(&sh.rules).list().iter().find(|r| r.agent == *agent && r.secret == *secret).cloned();
            let Some(rule) = found else {
                return ("missing", proto::write_err(w, &format!("no rule for {agent} and {secret}")));
            };
            let change = format!("remove the rule \"{} {agent} {secret}\"", rule.effect.as_str());
            change_rules(sh, req, agent, change, caller, peer, sock, w, |r| r.remove(agent, secret))
        }
    }
}

/// What the rules say about this request. Ask when there are no rules, or when the
/// asking chain cannot be read reliably: falling back to the prompt is never weaker.
fn rule_decision(sh: &Shared, sock: RawFd, pid: i32, name: &str) -> Decision {
    if lock(&sh.rules).list().is_empty() {
        return Decision::Ask;
    }
    let Some(chain) = agent_chain(sock, pid) else { return Decision::Ask };
    rules::decide(lock(&sh.rules).list(), &chain, name)
}

/// Adds, replaces or removes a rule after the user approves. Refused without a prompt
/// when the asking chain holds the agent the rule is about, or any agent that has a rule,
/// so an agent cannot ask to allow itself. `apply` returns false when there was nothing
/// to remove (another request removed it while the prompt was up).
#[allow(clippy::too_many_arguments)]
fn change_rules(
    sh: &Shared,
    req: &Request,
    agent: &str,
    change: String,
    caller: &str,
    peer: &Peer,
    sock: RawFd,
    w: &mut impl Write,
    apply: impl FnOnce(&mut Rules) -> io::Result<bool>,
) -> Reply {
    let Some(chain) = agent_chain(sock, peer.pid) else {
        return ("error", proto::write_err(w, "cannot identify the asking process"));
    };
    let blocked = rules::blocks_change(lock(&sh.rules).list(), &chain, Some(agent)).map(str::to_string);
    if let Some(name) = blocked {
        let msg = format!("\"{name}\" is in the asking chain; change rules from a terminal outside any agent");
        return ("refused", proto::write_err(w, &msg));
    }
    if let Some(refused) = gate(sh, ACTION_RULE, &req.log_name(), &[("change", change)], caller, peer, w) {
        return refused;
    }
    let applied = apply(&mut lock(&sh.rules));
    match applied {
        Ok(true) => ("changed", proto::write_ok(w, b"")),
        Ok(false) => ("missing", proto::write_err(w, "no such rule")),
        Err(e) => ("error", proto::write_err(w, &format!("cannot save rules: {e}"))),
    }
}

/// Process names (`/proc/<pid>/comm`) up the asking chain, nearest first, leaving out
/// the agent-keychain client itself. The names are read between two ancestry reads that
/// must match, with the asker alive, so each name belongs to that (pid, start time).
/// The names themselves are whatever each process chose to call itself.
fn agent_chain(sock: RawFd, pid: i32) -> Option<Vec<String>> {
    let pidfd = peer::peer_pidfd(sock).ok()?;
    let first = peer::ancestry(pid).ok()?;
    let names = first.iter().map(|&(p, _)| peer::comm(p)).collect::<io::Result<Vec<_>>>().ok()?;
    let again = peer::ancestry(pid).ok()?;
    if first.is_empty() || first != again || !peer::alive(&pidfd) {
        return None;
    }
    let skip = usize::from(names[0] == rules::CLIENT_NAME);
    Some(names.into_iter().skip(skip).collect())
}

/// Live grants, one per line: `<pid> <seconds left> <names> <program>`. The program is
/// last because its name may hold spaces. Grants that expired, or whose process is gone
/// or was replaced under the same pid, are dropped first.
fn grants_text(sh: &Shared) -> String {
    let mut grants = lock(&sh.grants);
    let now = Instant::now();
    grants.retain(|&(pid, start), g| g.until > now && peer::proc_stat(pid).is_ok_and(|(_, s)| s == start));
    let mut rows: Vec<_> = grants.iter().collect();
    rows.sort_by_key(|&(&(pid, _), _)| pid);
    rows.iter()
        .map(|&(&(pid, _), g)| {
            let left = (g.until - now).as_secs() + 1;
            let program = peer::comm(pid).unwrap_or_else(|_| "?".into());
            format!("{pid} {left} {} {program}", g.names.join(","))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Whether the asking process, or one of its ancestors, holds a live grant for `name`.
fn granted(sh: &Shared, sock: RawFd, pid: i32, name: &str) -> bool {
    let mut grants = lock(&sh.grants);
    let now = Instant::now();
    grants.retain(|_, g| g.until > now);
    if grants.is_empty() {
        return false;
    }
    let Some(chain) = verified_ancestry(sock, pid) else { return false };
    chain.iter().any(|id| grants.get(id).is_some_and(|g| g.names.iter().any(|n| n == name)))
}

/// The asking process and its ancestors as (pid, start time), read twice and compared,
/// with the asker confirmed alive through its pidfd. Without these checks, a process that
/// exits mid-request could leave its pid, or a parent's, to a process holding a grant.
fn verified_ancestry(sock: RawFd, pid: i32) -> Option<Vec<(i32, u64)>> {
    let pidfd = peer::peer_pidfd(sock).ok()?;
    let first = peer::ancestry(pid).ok()?;
    let again = peer::ancestry(pid).ok()?;
    (!first.is_empty() && first == again && peer::alive(&pidfd)).then_some(first)
}

/// 3600 -> "1h", 90 -> "90s", for the prompt.
fn duration(secs: u64) -> String {
    match secs {
        s if s % 3600 == 0 => format!("{}h", s / 3600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

fn missing(w: &mut impl Write, name: &str) -> Reply {
    ("missing", proto::write_err(w, &format!("no secret named {name}")))
}

/// Asks for approval. None when approved; otherwise the refusal already sent.
fn gate(
    sh: &Shared,
    action: &str,
    name: &str,
    details: &[(&str, String)],
    caller: &str,
    peer: &Peer,
    w: &mut impl Write,
) -> Option<Reply> {
    if let Some(wait) = lock(&sh.backoff).remaining() {
        let msg = format!("a recent request was denied; try again in {}s", wait.as_secs() + 1);
        return Some(("throttled", proto::write_err(w, &msg)));
    }
    let _open = match sh.prompt.try_lock() {
        Ok(g) => g,
        Err(TryLockError::Poisoned(p)) => p.into_inner(),
        Err(TryLockError::WouldBlock) => {
            let msg = "another approval prompt is open; try again when it closes";
            return Some(("busy", proto::write_err(w, msg)));
        }
    };
    match ask(sh, action, name, details, caller, peer) {
        Ok(true) => {
            lock(&sh.backoff).approved();
            None
        }
        Ok(false) => {
            lock(&sh.backoff).denied(sh.cfg.deny_backoff);
            Some(("denied", proto::write_denied(w)))
        }
        Err(e) => {
            eprintln!("agent-keychaind: approval: {e}");
            Some(("error", proto::write_err(w, &format!("approval failed: {e}"))))
        }
    }
}

/// Ok(true) approved, Ok(false) denied, Err when no decision could be made.
fn ask(sh: &Shared, action: &str, name: &str, details: &[(&str, String)], caller: &str, peer: &Peer) -> io::Result<bool> {
    let (program, status) = match &sh.cfg.approver {
        Some(program) => (
            program.display().to_string(),
            Command::new(program)
                .args([action, name, caller])
                .args(details.iter().map(|(k, v)| format!("{k}={v}")))
                .stdin(Stdio::null())
                .status()?,
        ),
        None => {
            // pid + start time + uid pins the subject, so a reused pid cannot inherit the answer.
            let (_, start) = peer::proc_stat(peer.pid)?;
            let mut pkcheck = Command::new(PKCHECK);
            for (k, v) in details {
                pkcheck.args(["--detail", k, v]);
            }
            let status = pkcheck
                .args(["--action-id", action])
                .args(["--process", &format!("{},{},{}", peer.pid, start, peer.uid)])
                .arg("--allow-user-interaction")
                .args(["--detail", "secret", name])
                .args(["--detail", "caller", caller])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .status()?;
            (PKCHECK.to_string(), status)
        }
    };
    // pkcheck(1): 0 authorized, 1 not authorized, 2 no authentication agent,
    // 3 dialog dismissed, 127 error. The approver hook follows the same codes.
    match status.code() {
        Some(0) => Ok(true),
        Some(1 | 3) => Ok(false),
        Some(2) => Err(io::Error::other("no polkit authentication agent is running")),
        _ => Err(io::Error::other(format!("{program}: {status}"))),
    }
}

fn open_log(state_dir: &Path) -> io::Result<File> {
    OpenOptions::new().append(true).create(true).mode(0o600).open(state_dir.join("log"))
}

/// The last LOG_TAIL lines, from `log.1` too when `log` was just rotated.
fn log_tail(state_dir: &Path) -> Vec<u8> {
    let mut lines = tail_lines(&state_dir.join("log"));
    if lines.len() < LOG_TAIL {
        let mut older = tail_lines(&state_dir.join("log.1"));
        older.append(&mut lines);
        lines = older;
    }
    lines[lines.len().saturating_sub(LOG_TAIL)..].join(&b'\n')
}

/// The last LOG_TAIL lines of one file, reading only its end.
fn tail_lines(path: &Path) -> Vec<Vec<u8>> {
    const WINDOW: u64 = 64 * 1024;
    let Ok(mut f) = File::open(path) else { return Vec::new() };
    let start = f.metadata().map_or(0, |m| m.len()).saturating_sub(WINDOW);
    let mut buf = Vec::new();
    if f.seek(SeekFrom::Start(start)).is_err() || f.take(WINDOW).read_to_end(&mut buf).is_err() {
        return Vec::new();
    }
    let mut text = buf.as_slice();
    if start > 0 {
        // Drop the partial first line.
        text = text.iter().position(|&b| b == b'\n').map_or(&[][..], |i| &text[i + 1..]);
    }
    let lines: Vec<&[u8]> = text.split(|&b| b == b'\n').filter(|l| !l.is_empty()).collect();
    lines[lines.len().saturating_sub(LOG_TAIL)..].iter().map(|l| l.to_vec()).collect()
}

fn record(sh: &Shared, verb: &str, name: &str, peer: &Peer, caller: &str, outcome: &str) {
    let line = format!(
        "{} {} {} uid={} pid={} caller=\"{}\" {}\n",
        time::utc_now(),
        verb,
        name,
        peer.uid,
        peer.pid,
        caller,
        outcome
    );
    let mut log = lock(&sh.log);
    if let Err(e) = log.write_all(line.as_bytes()) {
        eprintln!("agent-keychaind: log: {e}");
    }
    if log.metadata().is_ok_and(|m| m.len() >= sh.cfg.log_max) {
        let dir = &sh.cfg.state_dir;
        match fs::rename(dir.join("log"), dir.join("log.1")).and_then(|()| open_log(dir)) {
            Ok(fresh) => *log = fresh,
            Err(e) => eprintln!("agent-keychaind: log rotate: {e}"),
        }
    }
}
