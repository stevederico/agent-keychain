//! agent-keychain: the client agents and people run.

use agent_keychain::crypto::{SecretBytes, wipe};
use agent_keychain::names::valid_name;
use agent_keychain::proto::{self, MAX_SECRET, Request, Response};
use agent_keychain::scan;
use agent_keychain::sys;
use std::env;
use std::ffi::OsString;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::raw::c_int;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitCode};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

const SOCKET: &str = "/run/agent-keychain/sock";
const DEFAULT_ALLOW_SECS: u64 = 3600;
/// How-to for AI agents, printed by `skill`. Ships in the binary, so it always matches.
const SKILL: &str = include_str!("../skill.md");
const EXIT_DENIED: u8 = 2;
const EXIT_USAGE: u8 = 64;

const USAGE: &str = "usage: agent-keychain <command> [name]
       agent-keychain with <name>[,<name>...] [--for 1h] [--] <program> [args...]

commands:
  set <name>   store a secret, from stdin or a hidden prompt (asks you to approve)
  get <name>   print a secret (asks you to approve)
  list         list secret names (--json for a JSON array)
  rm <name>    delete a secret (asks you to approve)
  log          show recent requests (--json for an array of objects)
  skill        print the guide for AI agents (start here if you are one)
  --version    print the version
  scan [dir]   find secrets in plain files (.env, shell config, ~/.npmrc, ...).
               Read only; shows where, never the values. --json for scripts
  import <file>:<line>[=name]...
               store secrets that scan found, under one approval.
               --all imports everything scan finds. Files are left as they are
  with <names> <program>
               run a program that may get these secrets without a prompt, along
               with everything it starts, for 1h or --for (30m, 2h, at most 12h).
               Asks you to approve once

examples:
  GITHUB_TOKEN=$(agent-keychain get github) gh pr list
  agent-keychain with github,npm --for 2h -- claude

exit codes: 0 ok, 1 error, 2 denied, 64 usage";

fn socket_path() -> PathBuf {
    // Debug builds only, for tests. A release client always talks to the system daemon,
    // so an environment variable cannot redirect secrets to an impostor.
    #[cfg(debug_assertions)]
    if let Some(p) = env::var_os("AGENT_KEYCHAIN_SOCKET") {
        return p.into();
    }
    PathBuf::from(SOCKET)
}

fn main() -> ExitCode {
    // Other processes of this user cannot read our memory, environment or file
    // descriptors (/proc/<pid>/environ, /proc/<pid>/fd), where a secret passes through.
    // SAFETY: prctl(PR_SET_DUMPABLE, 0) has no pointer arguments.
    unsafe { sys::prctl(sys::PR_SET_DUMPABLE, 0 as std::os::raw::c_ulong) };
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("agent-keychain: {e}");
            ExitCode::FAILURE
        }
    }
}

fn name(s: &str) -> Result<String, String> {
    if valid_name(s) {
        Ok(s.to_string())
    } else {
        Err(format!("bad name {s:?}: use 1 to 64 of a-z, 0-9, '.', '_', '-'"))
    }
}

fn run() -> Result<ExitCode, String> {
    let mut os_args = env::args_os().skip(1);
    if os_args.next().is_some_and(|a| a == "with") {
        return with(os_args.collect());
    }
    let args: Vec<String> = env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let json = matches!(args.as_slice(), ["list" | "log", "--json"]);
    let req = match args.as_slice() {
        ["list"] | ["list", "--json"] => Request::List,
        ["log"] | ["log", "--json"] => Request::Log,
        ["get", n] => Request::Get(name(n)?),
        ["rm", n] => Request::Rm(name(n)?),
        ["set", n] => {
            let n = name(n)?;
            let value = read_secret(&n)?;
            Request::Set(n, value)
        }
        ["scan", rest @ ..] => return scan_cmd(rest),
        ["import", "--all"] => import_all()?,
        ["import", specs @ ..] if !specs.is_empty() => import(specs)?,
        ["-V" | "--version" | "version"] => {
            println!("agent-keychain {}", env!("CARGO_PKG_VERSION"));
            return Ok(ExitCode::SUCCESS);
        }
        ["skill"] => {
            print!("{SKILL}");
            return Ok(ExitCode::SUCCESS);
        }
        ["-h" | "--help" | "help"] => {
            println!("{USAGE}");
            return Ok(ExitCode::SUCCESS);
        }
        _ => {
            eprintln!("{USAGE}");
            return Ok(ExitCode::from(EXIT_USAGE));
        }
    };

    match request(&req)? {
        Response::Ok(data) => {
            print_ok(&req, &data, json).map_err(|e| e.to_string())?;
            Ok(ExitCode::SUCCESS)
        }
        Response::Denied => {
            eprintln!("agent-keychain: denied");
            Ok(ExitCode::from(EXIT_DENIED))
        }
        Response::Err(msg) => Err(msg),
    }
}

fn request(req: &Request) -> Result<Response, String> {
    let path = socket_path();
    let stream = UnixStream::connect(&path).map_err(|e| {
        format!("cannot reach agent-keychaind at {}: {e} (is the service running?)", path.display())
    })?;
    let mut w = &stream;
    proto::write_request(&mut w, req).map_err(|e| format!("send: {e}"))?;
    proto::read_response(&mut BufReader::new(&stream)).map_err(|e| format!("receive: {e}"))
}

/// `with <names> [--for 1h] [--] <program> [args...]`: asks once to let this process and
/// everything it starts get these secrets without a prompt, then becomes the program.
/// exec keeps the pid and start time the grant is tied to.
fn with(args: Vec<OsString>) -> Result<ExitCode, String> {
    let usage = || {
        eprintln!("{USAGE}");
        Ok(ExitCode::from(EXIT_USAGE))
    };
    let mut args = args.into_iter();
    let Some(list) = args.next() else { return usage() };
    let list = list.into_string().map_err(|_| "secret names must be utf-8".to_string())?;
    if !proto::valid_allow_list(&list) {
        return Err(format!("bad names {list:?}: comma-separated, each 1 to 64 of a-z, 0-9, '.', '_', '-'"));
    }
    let mut rest: Vec<OsString> = args.collect();
    let mut secs = DEFAULT_ALLOW_SECS;
    if rest.first().is_some_and(|a| a == "--for") {
        let d = rest.get(1).and_then(|d| d.to_str()).ok_or("--for needs a duration like 30m or 2h")?;
        secs = parse_duration(d)?;
        rest.drain(..2);
    }
    if rest.first().is_some_and(|a| a == "--") {
        rest.remove(0);
    }
    let Some((program, program_args)) = rest.split_first() else { return usage() };

    match request(&Request::Allow(list, secs))? {
        Response::Ok(_) => {}
        Response::Denied => {
            eprintln!("agent-keychain: denied");
            return Ok(ExitCode::from(EXIT_DENIED));
        }
        Response::Err(msg) => return Err(msg),
    }
    let err = Command::new(program).args(program_args).exec();
    Err(format!("cannot run {}: {err}", program.to_string_lossy()))
}

/// "90s", "30m", "2h" -> seconds, 1s to 12h.
fn parse_duration(s: &str) -> Result<u64, String> {
    let bad = || format!("bad duration {s:?}: use 30s, 30m or 2h, at most 12h");
    let unit = match s.chars().last() {
        Some('s') => 1,
        Some('m') => 60,
        Some('h') => 3600,
        _ => return Err(bad()),
    };
    let n: u64 = s[..s.len() - 1].parse().map_err(|_| bad())?;
    match n.checked_mul(unit) {
        Some(secs) if (1..=proto::MAX_ALLOW_SECS).contains(&secs) => Ok(secs),
        _ => Err(bad()),
    }
}

fn print_ok(req: &Request, data: &[u8], json: bool) -> io::Result<()> {
    let mut out = io::stdout().lock();
    if json {
        let text = String::from_utf8_lossy(data);
        let items: Vec<String> = match req {
            Request::List => text.lines().map(json_string).collect(),
            _ => text.lines().map(log_json).collect(),
        };
        writeln!(out, "[{}]", items.join(","))?;
        return out.flush();
    }
    match req {
        Request::Get(_) => {
            out.write_all(data)?;
            if is_tty(1) {
                out.write_all(b"\n")?;
            }
        }
        Request::List | Request::Log => {
            out.write_all(data)?;
            if !data.is_empty() {
                out.write_all(b"\n")?;
            }
        }
        Request::Set(n, _) | Request::SetMany(n, _) => {
            eprintln!("stored {n}");
            if matches!(env::args().nth(1).as_deref(), Some("import")) {
                eprintln!("The plain copy is still in that file. Remove it once nothing reads it from there.");
            }
        }
        Request::Rm(n) => eprintln!("removed {n}"),
        Request::Allow(..) => {}
    }
    out.flush()
}

fn home() -> Result<PathBuf, String> {
    env::var_os("HOME").map(PathBuf::from).ok_or_else(|| "HOME is not set".to_string())
}

/// `/home/me/x` -> `~/x`, for display.
fn tilde(p: &Path) -> String {
    match home().ok().and_then(|h| p.strip_prefix(&h).ok().map(Path::to_path_buf)) {
        Some(rest) => format!("~/{}", rest.display()),
        None => p.display().to_string(),
    }
}

/// `~/x` -> `/home/me/x`.
fn untilde(s: &str) -> Result<PathBuf, String> {
    match s.strip_prefix("~/") {
        Some(rest) => Ok(home()?.join(rest)),
        None => Ok(PathBuf::from(s)),
    }
}

fn scan_cmd(args: &[&str]) -> Result<ExitCode, String> {
    let json = args.contains(&"--json");
    let dirs: Vec<&str> = args.iter().copied().filter(|a| *a != "--json").collect();
    let files = if dirs.is_empty() {
        scan::home_files(&home()?)
    } else {
        dirs.iter().map(|d| untilde(d)).collect::<Result<Vec<_>, _>>()?.iter().flat_map(|d| scan::candidate_files(d, 8)).collect()
    };
    let found = scan::scan_files(&files);
    let mut out = io::stdout().lock();
    let write = |out: &mut io::StdoutLock, s: String| out.write_all(s.as_bytes()).map_err(|e| e.to_string());
    if json {
        let items: Vec<String> = found
            .iter()
            .map(|f| {
                format!(
                    "{{\"path\":{},\"line\":{},\"var\":{},\"preview\":{},\"name\":{}}}",
                    json_string(&f.path.to_string_lossy()),
                    f.line,
                    f.var.as_deref().map_or("null".into(), json_string),
                    json_string(&f.preview()),
                    json_string(&f.suggested_name())
                )
            })
            .collect();
        write(&mut out, format!("[{}]\n", items.join(",")))?;
        return Ok(ExitCode::SUCCESS);
    }
    for f in &found {
        let place = format!("{}:{}", tilde(&f.path), f.line);
        let var = f.var.as_deref().unwrap_or("-");
        write(&mut out, format!("{place}  {var}  {}  -> {}\n", f.preview(), f.suggested_name()))?;
    }
    let files_hit = {
        let mut p: Vec<&Path> = found.iter().map(|f| f.path.as_path()).collect();
        p.dedup();
        p.len()
    };
    match found.first() {
        None => eprintln!("no secrets found in {} files", files.len()),
        Some(f) => eprintln!(
            "{} secrets in {files_hit} files. Store one: agent-keychain import {}:{} [name]",
            found.len(),
            tilde(&f.path),
            f.line
        ),
    }
    Ok(ExitCode::SUCCESS)
}

/// `file:line` or `file:line=name`, as given to import.
fn parse_spec(spec: &str) -> Result<(PathBuf, usize, Option<String>), String> {
    let (place, name_arg) = match spec.rsplit_once('=') {
        Some((p, n)) if p.rsplit_once(':').is_some_and(|(_, l)| l.parse::<usize>().is_ok()) => (p, Some(name(n)?)),
        _ => (spec, None),
    };
    let (file, line) = place.rsplit_once(':').ok_or("use <file>:<line>, as scan prints it")?;
    let line = line.parse().map_err(|_| format!("bad line number in {spec:?}"))?;
    Ok((untilde(file)?, line, name_arg))
}

/// The store request for the secrets scan found at these `file:line[=name]` specs.
fn import(specs: &[&str]) -> Result<Request, String> {
    let mut items = Vec::new();
    for spec in specs {
        let (path, line, name_arg) = parse_spec(spec)?;
        let found = scan::finding_at(&path, line).map_err(|e| e.to_string())?;
        items.push((name_arg.unwrap_or_else(|| found.suggested_name()), found));
    }
    store_request(items, false)
}

/// Everything a home scan finds, each value once, under unique names.
fn import_all() -> Result<Request, String> {
    let mut items: Vec<(String, scan::Finding)> = Vec::new();
    for f in scan::scan_files(&scan::home_files(&home()?)) {
        if !items.iter().any(|(_, g)| g.value == f.value) {
            items.push((f.suggested_name(), f));
        }
    }
    store_request(items, true)
}

/// One SET, or a SETMANY so a batch needs a single approval. Never overwrites: names
/// already in the vault are refused, or with `rename` get a -2, -3 suffix.
fn store_request(mut items: Vec<(String, scan::Finding)>, rename: bool) -> Result<Request, String> {
    if items.is_empty() {
        return Err("nothing to import".into());
    }
    if items.len() > proto::MAX_BATCH {
        return Err(format!("at most {} at a time", proto::MAX_BATCH));
    }
    let stored: Vec<String> = match request(&Request::List)? {
        Response::Ok(data) => String::from_utf8_lossy(&data).lines().map(str::to_string).collect(),
        Response::Err(msg) => return Err(msg),
        Response::Denied => return Err("denied".into()),
    };
    let mut taken = stored.clone();
    for (n, _) in &mut items {
        if rename && taken.contains(n) {
            let base = n.clone();
            *n = (2..).map(|i| format!("{base}-{i}")).find(|c| !taken.contains(c) && valid_name(c)).unwrap_or(base);
        }
        if stored.contains(n) {
            return Err(format!("{n} is already stored. Name it with <file>:<line>=<name>, or rm it first"));
        }
        if taken.contains(n) {
            return Err(format!("two secrets would both be named {n}. Name them with <file>:<line>=<name>"));
        }
        taken.push(n.clone());
    }
    for (n, f) in &items {
        eprintln!("importing {} from {}:{} as {n}", f.preview(), tilde(&f.path), f.line);
    }
    let mut items: Vec<(String, SecretBytes)> =
        items.into_iter().map(|(n, f)| (n, SecretBytes::from_slice(f.value.as_bytes()))).collect();
    if items.len() == 1 {
        let (n, v) = items.remove(0);
        return Ok(Request::Set(n, v));
    }
    let list = items.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(",");
    Ok(Request::SetMany(list, items))
}

fn json_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// One daemon log line as a JSON object. The daemon writes
/// `TIME VERB NAME uid=UID pid=PID caller="CALLER" OUTCOME`; anything else becomes {"raw": ...}.
fn log_json(line: &str) -> String {
    let parse = || {
        let (time, rest) = line.split_once(' ')?;
        let (verb, rest) = rest.split_once(' ')?;
        let (name, rest) = rest.split_once(' ')?;
        let (uid, rest) = rest.strip_prefix("uid=")?.split_once(' ')?;
        let (pid, rest) = rest.strip_prefix("pid=")?.split_once(' ')?;
        let (caller, outcome) = rest.strip_prefix("caller=\"")?.rsplit_once("\" ")?;
        let (uid, pid): (u32, i32) = (uid.parse().ok()?, pid.parse().ok()?);
        let name = if name == "-" { "null".to_string() } else { json_string(name) };
        Some(format!(
            "{{\"time\":{},\"request\":{},\"name\":{name},\"uid\":{uid},\"pid\":{pid},\"caller\":{},\"outcome\":{}}}",
            json_string(time),
            json_string(verb),
            json_string(caller),
            json_string(outcome)
        ))
    };
    parse().unwrap_or_else(|| format!("{{\"raw\":{}}}", json_string(line)))
}

fn is_tty(fd: c_int) -> bool {
    // SAFETY: isatty only inspects the descriptor.
    unsafe { sys::isatty(fd) == 1 }
}

/// Reads the secret from a hidden prompt on a terminal, else all of stdin.
/// One trailing newline is dropped.
fn read_secret(name: &str) -> Result<SecretBytes, String> {
    let limit = MAX_SECRET + 2;
    // Fixed capacity, so reading never reallocates and leaves copies behind.
    let mut raw = Vec::with_capacity(limit);
    let stdin = io::stdin();
    let read = if is_tty(0) {
        eprint!("Secret for {name}: ");
        let _echo = EchoOff::new(0).map_err(|e| format!("terminal: {e}"))?;
        let r = stdin.lock().take(limit as u64).read_until(b'\n', &mut raw);
        eprintln!();
        r
    } else {
        stdin.lock().take(limit as u64).read_to_end(&mut raw)
    };
    read.map_err(|e| format!("read secret: {e}"))?;

    let mut end = raw.len();
    if raw[..end].ends_with(b"\n") {
        end -= 1;
        if raw[..end].ends_with(b"\r") {
            end -= 1;
        }
    }
    let result = match end {
        0 => Err("empty secret".to_string()),
        n if n > MAX_SECRET => Err(format!("secret longer than {MAX_SECRET} bytes")),
        n => Ok(SecretBytes::from_slice(&raw[..n])),
    };
    wipe(&mut raw);
    result
}

/// The terminal to restore if a signal kills us while echo is off.
static SAVED: OnceLock<(c_int, sys::termios)> = OnceLock::new();
static ECHO_IS_OFF: AtomicBool = AtomicBool::new(false);
const FATAL_SIGNALS: [c_int; 4] = [sys::SIGHUP, sys::SIGINT, sys::SIGQUIT, sys::SIGTERM];

/// Puts echo back, then dies of the same signal. Only async-signal-safe calls.
extern "C" fn on_fatal_signal(sig: c_int) {
    if ECHO_IS_OFF.swap(false, Ordering::SeqCst)
        && let Some((fd, t)) = SAVED.get()
    {
        // SAFETY: restores a termios saved from this terminal; tcsetattr is signal-safe.
        unsafe { sys::tcsetattr(*fd, sys::TCSANOW, t) };
    }
    // SAFETY: signal and raise are async-signal-safe and take no pointers.
    unsafe {
        sys::signal(sig, sys::SIG_DFL);
        sys::raise(sig);
    }
}

/// Turns terminal echo off until dropped, or until Ctrl-C and friends kill the process.
struct EchoOff {
    fd: c_int,
    saved: sys::termios,
}

impl EchoOff {
    fn new(fd: c_int) -> io::Result<EchoOff> {
        // SAFETY: termios is plain integers, so all-zero is a valid value to fill in.
        let mut t: sys::termios = unsafe { std::mem::zeroed() };
        // SAFETY: `t` is a writable termios.
        if unsafe { sys::tcgetattr(fd, &mut t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let saved = t;
        // One prompt per process, so the first saved state is the one to restore.
        let _ = SAVED.set((fd, saved));
        ECHO_IS_OFF.store(true, Ordering::SeqCst);
        for sig in FATAL_SIGNALS {
            // SAFETY: the handler is an extern "C" fn(c_int) that only makes signal-safe calls.
            unsafe { sys::signal(sig, on_fatal_signal as *const () as sys::sighandler_t) };
        }
        let guard = EchoOff { fd, saved };
        t.c_lflag &= !sys::ECHO;
        // SAFETY: `t` is a valid termios read from this terminal.
        if unsafe { sys::tcsetattr(fd, sys::TCSANOW, &t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(guard)
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        // SAFETY: restores the termios saved from this terminal.
        unsafe { sys::tcsetattr(self.fd, sys::TCSANOW, &self.saved) };
        ECHO_IS_OFF.store(false, Ordering::SeqCst);
        for sig in FATAL_SIGNALS {
            // SAFETY: SIG_DFL takes no pointers.
            unsafe { sys::signal(sig, sys::SIG_DFL) };
        }
    }
}
