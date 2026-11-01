//! agent-keychaind: holds the vault and hands out secrets after polkit approval.
//! Runs as the `agent-keychain` system user (see dist/agent-keychaind.service).

use agent_keychain::crypto::{Key, SecretBytes, random};
use agent_keychain::peer::{self, Peer};
use agent_keychain::proto::{self, Request};
use agent_keychain::vault::Vault;
use agent_keychain::{sys, time};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::raw::c_ulong;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

const DEFAULT_SOCKET: &str = "/run/agent-keychain/sock";
const DEFAULT_STATE: &str = "/var/lib/agent-keychain";
const CREDENTIAL_NAME: &str = "vault-key";
const PKCHECK: &str = "/usr/bin/pkcheck";
const ACTION_READ: &str = "dev.agent-keychain.read";
const ACTION_WRITE: &str = "dev.agent-keychain.write";
const LOG_TAIL: usize = 50;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

const USAGE: &str = "usage: agent-keychaind [--owner-uid UID] [--socket PATH] [--state-dir DIR]
                      [--key-file PATH] [--approver PROGRAM]
       agent-keychaind --gen-key   (print 32 random bytes, for systemd-creds)

The owner uid may also come from AGENT_KEYCHAIN_OWNER_UID. Without --key-file the
vault key is read from the systemd credential \"vault-key\".";

struct Config {
    socket: PathBuf,
    state_dir: PathBuf,
    key_file: Option<PathBuf>,
    owner_uid: u32,
    /// Test hook: a program run as `PROGRAM <action> <name> <caller>`; exit 0 approves.
    /// Without it, approval goes through polkit.
    approver: Option<PathBuf>,
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

    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{arg} needs a value\n\n{USAGE}"));
        match arg.as_str() {
            "--gen-key" => return Ok(Mode::GenKey),
            "--socket" => socket = value()?.into(),
            "--state-dir" => state_dir = value()?.into(),
            "--key-file" => key_file = Some(value()?.into()),
            "--approver" => approver = Some(value()?.into()),
            "--owner-uid" => owner = Some(value()?),
            "-h" | "--help" => return Err(USAGE.into()),
            _ => return Err(format!("unknown argument {arg}\n\n{USAGE}")),
        }
    }
    let owner = owner.ok_or_else(|| format!("no owner uid\n\n{USAGE}"))?;
    let owner_uid = owner.parse().map_err(|_| format!("bad owner uid {owner:?}"))?;
    Ok(Mode::Run(Config { socket, state_dir, key_file, owner_uid, approver }))
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
    let log = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(cfg.state_dir.join("log"))
        .map_err(|e| format!("log: {e}"))?;

    let _ = fs::remove_file(&cfg.socket);
    let listener = UnixListener::bind(&cfg.socket).map_err(|e| format!("{}: {e}", cfg.socket.display()))?;
    // Anyone may connect; only the owner uid is served, and every secret needs approval.
    fs::set_permissions(&cfg.socket, fs::Permissions::from_mode(0o666))
        .map_err(|e| format!("{}: {e}", cfg.socket.display()))?;
    eprintln!("agent-keychaind: serving uid {} on {}", cfg.owner_uid, cfg.socket.display());

    let shared = Arc::new(Shared { cfg, vault: Mutex::new(vault), log: Mutex::new(log) });
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
    if peer.uid != sh.cfg.owner_uid {
        return proto::write_err(&mut w, "this keychain belongs to another user");
    }

    let req = match proto::read_request(&mut BufReader::new(stream)) {
        Ok(r) => r,
        Err(e) => return proto::write_err(&mut w, &e.to_string()),
    };
    let caller = peer::describe_caller(peer.pid);

    let outcome = match &req {
        Request::List => {
            let names = lock(&sh.vault).names().collect::<Vec<_>>().join("\n");
            return proto::write_ok(&mut w, names.as_bytes());
        }
        Request::Log => {
            let log = fs::read_to_string(sh.cfg.state_dir.join("log")).unwrap_or_default();
            let lines: Vec<&str> = log.lines().collect();
            let tail = lines[lines.len().saturating_sub(LOG_TAIL)..].join("\n");
            return proto::write_ok(&mut w, tail.as_bytes());
        }
        Request::Get(name) => {
            if !lock(&sh.vault).contains(name) {
                proto::write_err(&mut w, &format!("no secret named {name}"))?;
                "missing"
            } else if !approved(sh, ACTION_READ, name, &caller, &peer, &mut w)? {
                "denied"
            } else {
                // Read after approval: the value may have changed while the prompt was up.
                let value = lock(&sh.vault).get(name);
                match value {
                    Ok(Some(v)) => {
                        proto::write_ok(&mut w, &v)?;
                        "allowed"
                    }
                    Ok(None) => {
                        proto::write_err(&mut w, &format!("no secret named {name}"))?;
                        "missing"
                    }
                    Err(e) => {
                        proto::write_err(&mut w, &format!("cannot open {name}: {e}"))?;
                        "error"
                    }
                }
            }
        }
        Request::Set(name, value) => {
            if !approved(sh, ACTION_WRITE, name, &caller, &peer, &mut w)? {
                "denied"
            } else {
                let saved = lock(&sh.vault).set(name, value);
                match saved {
                    Ok(()) => {
                        proto::write_ok(&mut w, b"")?;
                        "stored"
                    }
                    Err(e) => {
                        proto::write_err(&mut w, &format!("cannot save: {e}"))?;
                        "error"
                    }
                }
            }
        }
        Request::Rm(name) => {
            if !lock(&sh.vault).contains(name) {
                proto::write_err(&mut w, &format!("no secret named {name}"))?;
                "missing"
            } else if !approved(sh, ACTION_WRITE, name, &caller, &peer, &mut w)? {
                "denied"
            } else {
                let removed = lock(&sh.vault).remove(name);
                match removed {
                    Ok(_) => {
                        proto::write_ok(&mut w, b"")?;
                        "removed"
                    }
                    Err(e) => {
                        proto::write_err(&mut w, &format!("cannot save: {e}"))?;
                        "error"
                    }
                }
            }
        }
    };
    record(sh, &req, &peer, &caller, outcome);
    Ok(())
}

/// Asks for approval. On a denial or an approver failure, writes the response itself.
fn approved(
    sh: &Shared,
    action: &str,
    name: &str,
    caller: &str,
    peer: &Peer,
    w: &mut impl Write,
) -> io::Result<bool> {
    match ask(sh, action, name, caller, peer) {
        Ok(true) => Ok(true),
        Ok(false) => {
            proto::write_denied(w)?;
            Ok(false)
        }
        Err(e) => {
            proto::write_err(w, &format!("approval failed: {e}"))?;
            Ok(false)
        }
    }
}

fn ask(sh: &Shared, action: &str, name: &str, caller: &str, peer: &Peer) -> io::Result<bool> {
    let status = match &sh.cfg.approver {
        Some(program) => {
            Command::new(program).args([action, name, caller]).stdin(Stdio::null()).status()?
        }
        None => {
            // pid + start time + uid pins the subject, so a reused pid cannot inherit the answer.
            let (_, start) = peer::proc_stat(peer.pid)?;
            Command::new(PKCHECK)
                .args(["--action-id", action])
                .args(["--process", &format!("{},{},{}", peer.pid, start, peer.uid)])
                .arg("--allow-user-interaction")
                .args(["--detail", "secret", name])
                .args(["--detail", "caller", caller])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .status()?
        }
    };
    Ok(status.code() == Some(0))
}

fn record(sh: &Shared, req: &Request, peer: &Peer, caller: &str, outcome: &str) {
    let line = format!(
        "{} {} {} uid={} pid={} caller=\"{}\" {}\n",
        time::utc_now(),
        req.verb(),
        req.name().unwrap_or("-"),
        peer.uid,
        peer.pid,
        caller,
        outcome
    );
    let mut log = lock(&sh.log);
    if let Err(e) = log.write_all(line.as_bytes()) {
        eprintln!("agent-keychaind: log: {e}");
    }
}
