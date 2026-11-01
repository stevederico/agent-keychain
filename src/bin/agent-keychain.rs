//! agent-keychain: the client agents and people run.

use agent_keychain::crypto::{SecretBytes, wipe};
use agent_keychain::names::valid_name;
use agent_keychain::proto::{self, MAX_SECRET, Request, Response};
use agent_keychain::sys;
use std::env;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::raw::c_int;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;

const SOCKET: &str = "/run/agent-keychain/sock";
const EXIT_DENIED: u8 = 2;
const EXIT_USAGE: u8 = 64;

const USAGE: &str = "usage: agent-keychain <command> [name]

commands:
  set <name>   store a secret, from stdin or a hidden prompt (asks you to approve)
  get <name>   print a secret (asks you to approve)
  list         list secret names
  rm <name>    delete a secret (asks you to approve)
  log          show recent requests

example:
  GITHUB_TOKEN=$(agent-keychain get github) gh pr list

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
    let args: Vec<String> = env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let req = match args.as_slice() {
        ["list"] => Request::List,
        ["log"] => Request::Log,
        ["get", n] => Request::Get(name(n)?),
        ["rm", n] => Request::Rm(name(n)?),
        ["set", n] => {
            let n = name(n)?;
            let value = read_secret(&n)?;
            Request::Set(n, value)
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

    let path = socket_path();
    let stream = UnixStream::connect(&path).map_err(|e| {
        format!("cannot reach agent-keychaind at {}: {e} (is the service running?)", path.display())
    })?;
    let mut w = &stream;
    proto::write_request(&mut w, &req).map_err(|e| format!("send: {e}"))?;
    let resp = proto::read_response(&mut BufReader::new(&stream)).map_err(|e| format!("receive: {e}"))?;

    match resp {
        Response::Ok(data) => {
            print_ok(&req, &data).map_err(|e| e.to_string())?;
            Ok(ExitCode::SUCCESS)
        }
        Response::Denied => {
            eprintln!("agent-keychain: denied");
            Ok(ExitCode::from(EXIT_DENIED))
        }
        Response::Err(msg) => Err(msg),
    }
}

fn print_ok(req: &Request, data: &[u8]) -> io::Result<()> {
    let mut out = io::stdout().lock();
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
        Request::Set(n, _) => eprintln!("stored {n}"),
        Request::Rm(n) => eprintln!("removed {n}"),
    }
    out.flush()
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

/// Turns terminal echo off until dropped.
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
        t.c_lflag &= !sys::ECHO;
        // SAFETY: `t` is a valid termios read from this terminal.
        if unsafe { sys::tcsetattr(fd, sys::TCSANOW, &t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(EchoOff { fd, saved })
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        // SAFETY: restores the termios saved from this terminal.
        unsafe { sys::tcsetattr(self.fd, sys::TCSANOW, &self.saved) };
    }
}
