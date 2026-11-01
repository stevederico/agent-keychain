//! End to end: a real daemon and client, with a scripted approver in place of polkit.
//!
//! Debug builds only. A release client ignores AGENT_KEYCHAIN_SOCKET and would talk to
//! the real system daemon, so `cargo test --release` must not run these.
#![cfg(debug_assertions)]

use agent_keychain::peer::current_uid;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

const DAEMON: &str = env!("CARGO_BIN_EXE_agent-keychaind");
const CLIENT: &str = env!("CARGO_BIN_EXE_agent-keychain");

struct Env {
    dir: PathBuf,
    daemon: Option<Child>,
    backoff: &'static str,
}

impl Env {
    fn new(tag: &str) -> Env {
        let dir = std::env::temp_dir().join(format!("akc-it-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("key"), [7u8; 32]).unwrap();
        // Approves unless a file named "deny" exists; records each call. A file named
        // "slow" holds the prompt open until it is removed.
        let script = format!(
            "#!/bin/sh\necho \"$1 $2 $3\" >> '{0}/approvals'\nwhile [ -e '{0}/slow' ]; do sleep 0.05; done\n[ -e '{0}/deny' ] && exit 1\nexit 0\n",
            dir.display()
        );
        let approver = dir.join("approve.sh");
        fs::write(&approver, script).unwrap();
        fs::set_permissions(&approver, fs::Permissions::from_mode(0o755)).unwrap();
        Env { dir, daemon: None, backoff: "0" }
    }

    /// The socket is relative to `dir` (both processes run there) to stay under the
    /// 108-byte sun_path limit whatever TMPDIR is.
    fn daemon_cmd(&self, owner: u32) -> Command {
        let mut c = Command::new(DAEMON);
        c.current_dir(&self.dir)
            .args(["--socket", "sock", "--state-dir", "state", "--key-file", "key"])
            .args(["--owner-uid", &owner.to_string(), "--approver", "./approve.sh"])
            .args(["--deny-backoff", self.backoff])
            .stdin(Stdio::null())
            .stderr(Stdio::piped());
        c
    }

    fn start(&mut self, owner: u32) {
        let _ = fs::remove_file(self.dir.join("sock"));
        let mut child = self.daemon_cmd(owner).spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !self.dir.join("sock").exists() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("daemon exited early: {status}");
            }
            assert!(Instant::now() < deadline, "daemon did not start");
            sleep(Duration::from_millis(20));
        }
        self.daemon = Some(child);
    }

    fn stop(&mut self) {
        if let Some(mut c) = self.daemon.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    /// Runs the client; returns (exit code, stdout, stderr).
    fn client(&self, args: &[&str], stdin: &[u8]) -> (i32, String, String) {
        summarize(self.spawn_client(args, stdin).wait_with_output().unwrap())
    }

    fn spawn_client(&self, args: &[&str], stdin: &[u8]) -> Child {
        let mut child = Command::new(CLIENT)
            .current_dir(&self.dir)
            .env("AGENT_KEYCHAIN_SOCKET", "sock")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        child
    }

    fn path(&self, p: &str) -> PathBuf {
        self.dir.join(p)
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        self.stop();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn summarize(out: Output) -> (i32, String, String) {
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn read(p: &Path) -> String {
    fs::read_to_string(p).unwrap_or_default()
}

#[test]
fn full_flow() {
    let mut env = Env::new("flow");
    env.start(current_uid());

    assert_eq!(env.client(&["set", "github"], b"ghp_test123\n").0, 0);
    assert_eq!(env.client(&["set", "stripe"], b"sk_test_456").0, 0);
    assert_eq!(env.client(&["list"], b""), (0, "github\nstripe\n".into(), String::new()));
    assert_eq!(env.client(&["get", "github"], b"").1, "ghp_test123", "trailing newline dropped, none added");

    // Approver saw the right action, name and caller chain.
    let approvals = read(&env.path("approvals"));
    assert!(approvals.contains("dev.agent-keychain.write github agent-keychain"), "{approvals}");
    assert!(approvals.contains("dev.agent-keychain.read github agent-keychain"), "{approvals}");

    // Denied: exit 2, nothing on stdout.
    fs::write(env.path("deny"), "").unwrap();
    let (code, out, err) = env.client(&["get", "github"], b"");
    assert_eq!((code, out.as_str()), (2, ""), "{err}");
    assert_eq!(env.client(&["rm", "github"], b"").0, 2);
    assert_eq!(env.client(&["set", "github"], b"overwrite").0, 2);
    fs::remove_file(env.path("deny")).unwrap();
    assert_eq!(env.client(&["get", "github"], b"").1, "ghp_test123", "denied writes changed nothing");

    // Missing secrets fail without asking.
    let before = read(&env.path("approvals")).lines().count();
    let (code, _, err) = env.client(&["get", "nope"], b"");
    assert_eq!(code, 1);
    assert!(err.contains("no secret named nope"), "{err}");
    assert_eq!(read(&env.path("approvals")).lines().count(), before);

    // Plaintext never touches the disk.
    let vault = fs::read(env.path("state/vault")).unwrap();
    assert!(!vault.windows(11).any(|w| w == b"ghp_test123"));
    assert_eq!(fs::metadata(env.path("state/vault")).unwrap().permissions().mode() & 0o777, 0o600);

    // Survives a restart with the same key.
    env.stop();
    env.start(current_uid());
    assert_eq!(env.client(&["get", "stripe"], b"").1, "sk_test_456");
    assert_eq!(env.client(&["rm", "stripe"], b"").0, 0);
    assert_eq!(env.client(&["list"], b"").1, "github\n");

    // Log records outcomes but never values.
    let (code, log, _) = env.client(&["log"], b"");
    assert_eq!(code, 0);
    for want in ["SET github", "GET github", "allowed", "denied", "GET nope", "missing", "RM stripe", "removed"]
        .into_iter()
        .chain(["LIST - ", "listed"])
    {
        assert!(log.contains(want), "log lacks {want:?}:\n{log}");
    }
    assert!(!log.contains("ghp_test123") && !log.contains("sk_test_456"));

    // JSON for scripts and agents.
    assert_eq!(env.client(&["list", "--json"], b"").1, "[\"github\"]\n");
    let (code, json, _) = env.client(&["log", "--json"], b"");
    assert_eq!(code, 0);
    assert!(json.starts_with("[{\"time\":\"") && json.ends_with("}]\n"), "{json}");
    assert!(json.contains("\"request\":\"GET\",\"name\":\"github\""), "{json}");
    assert!(json.contains("\"request\":\"LIST\",\"name\":null"), "{json}");
    assert!(json.contains("\"caller\":\"agent-keychain"), "{json}");
    assert!(!json.contains("\"raw\""), "every line parses: {json}");
}

#[test]
fn denials_back_off() {
    let mut env = Env::new("backoff");
    env.backoff = "60";
    env.start(current_uid());
    assert_eq!(env.client(&["set", "github"], b"tok").0, 0);

    fs::write(env.path("deny"), "").unwrap();
    assert_eq!(env.client(&["get", "github"], b"").0, 2);
    fs::remove_file(env.path("deny")).unwrap();

    // No prompt during the backoff, even for a request the user would approve.
    let before = read(&env.path("approvals")).lines().count();
    let (code, out, err) = env.client(&["get", "github"], b"");
    assert_eq!((code, out.as_str()), (1, ""), "{err}");
    assert!(err.contains("try again in"), "{err}");
    assert_eq!(read(&env.path("approvals")).lines().count(), before, "approver must not run");
    // Requests that never prompt are not held back.
    assert_eq!(env.client(&["list"], b"").1, "github\n");
    assert!(read(&env.path("state/log")).contains("throttled"));
}

#[test]
fn one_prompt_at_a_time() {
    let mut env = Env::new("busy");
    env.start(current_uid());
    assert_eq!(env.client(&["set", "github"], b"tok").0, 0);

    fs::write(env.path("slow"), "").unwrap();
    let first = env.spawn_client(&["get", "github"], b"");
    let deadline = Instant::now() + Duration::from_secs(5);
    while read(&env.path("approvals")).lines().count() < 2 {
        assert!(Instant::now() < deadline, "first prompt never opened");
        sleep(Duration::from_millis(20));
    }
    let (code, _, err) = env.client(&["rm", "github"], b"");
    assert_eq!(code, 1);
    assert!(err.contains("another approval prompt is open"), "{err}");

    fs::remove_file(env.path("slow")).unwrap();
    assert_eq!(summarize(first.wait_with_output().unwrap()).1, "tok");
    assert_eq!(read(&env.path("approvals")).lines().count(), 2, "second request never prompted");
    assert!(read(&env.path("state/log")).contains("busy"));
}

#[test]
fn with_skips_prompts_for_its_programs() {
    let mut env = Env::new("with");
    env.start(current_uid());
    assert_eq!(env.client(&["set", "github"], b"tok").0, 0);
    assert_eq!(env.client(&["set", "stripe"], b"sk").0, 0);
    let prompts = || read(&env.path("approvals")).lines().count();

    // One prompt for the grant; the program and its children then get github freely.
    let before = prompts();
    let script = format!("{CLIENT} get github; echo; {CLIENT} get github");
    let (code, out, err) = env.client(&["with", "github", "--for", "1m", "--", "sh", "-c", &script], b"");
    assert_eq!((code, out.as_str()), (0, "tok\ntok"), "{err}");
    assert_eq!(prompts(), before + 1);
    assert!(read(&env.path("approvals")).contains("dev.agent-keychain.allow github"));

    // Secrets outside the grant still ask, and so does everyone outside the program.
    let (code, out, _) = env.client(&["with", "github", CLIENT, "get", "stripe"], b"");
    assert_eq!((code, out.as_str()), (0, "sk"));
    assert_eq!(prompts(), before + 3, "grant prompt, then stripe prompt");
    assert_eq!(env.client(&["get", "github"], b"").0, 0);
    assert_eq!(prompts(), before + 4);

    // Grants expire.
    let script = format!("sleep 1.2; {CLIENT} get github");
    assert_eq!(env.client(&["with", "github", "--for", "1s", "sh", "-c", &script], b"").1, "tok");
    assert_eq!(prompts(), before + 6, "grant prompt, then a prompt after expiry");

    // Denied: the program never runs.
    fs::write(env.path("deny"), "").unwrap();
    let (code, out, _) = env.client(&["with", "github", "--", "echo", "ran"], b"");
    assert_eq!((code, out.as_str()), (2, ""));

    let log = read(&env.path("state/log"));
    for want in ["ALLOW github", "approved", "allowed-by-grant"] {
        assert!(log.contains(want), "log lacks {want:?}:\n{log}");
    }
}

#[test]
fn with_bad_input() {
    let mut env = Env::new("withbad");
    env.start(current_uid());
    assert_eq!(env.client(&["set", "github"], b"tok").0, 0);
    assert_eq!(env.client(&["with"], b"").0, 64);
    assert_eq!(env.client(&["with", "github"], b"").0, 64, "no program");
    assert_eq!(env.client(&["with", "github", "--for", "1h"], b"").0, 64, "no program");
    for bad in [&["with", "github", "--for", "13h", "true"][..], &["with", "github", "--for", "5", "true"],
        &["with", "github,github", "true"], &["with", "Bad", "true"], &["with", "nope", "true"]] {
        assert_eq!(env.client(bad, b"").0, 1, "{bad:?}");
    }
    assert!(!env.path("approvals").exists() || !read(&env.path("approvals")).contains("allow"), "never prompted");
}

#[test]
fn tells_systemd_when_ready() {
    let env = Env::new("notify");
    let notify = std::os::unix::net::UnixDatagram::bind(env.path("notify")).unwrap();
    notify.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut daemon = env.daemon_cmd(current_uid()).env("NOTIFY_SOCKET", env.path("notify")).spawn().unwrap();
    let mut buf = [0u8; 64];
    let n = notify.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"READY=1");
    assert!(env.path("sock").exists(), "ready only once the socket is up");
    let _ = daemon.kill();
    let _ = daemon.wait();
}

#[test]
fn wrong_key_refuses_to_start() {
    let mut env = Env::new("wrongkey");
    env.start(current_uid());
    assert_eq!(env.client(&["set", "github"], b"tok").0, 0);
    env.stop();

    fs::write(env.path("key"), [9u8; 32]).unwrap();
    let out = env.daemon_cmd(current_uid()).output().unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("authentication failed"), "{err}");
}

#[test]
fn other_users_are_refused() {
    let mut env = Env::new("owner");
    env.start(current_uid() + 1);
    let (code, _, err) = env.client(&["list"], b"");
    assert_eq!(code, 1);
    assert!(err.contains("belongs to another user"), "{err}");
    assert!(!env.path("approvals").exists(), "approver must not run");
    let log = read(&env.path("state/log"));
    assert!(log.contains("CONNECT - ") && log.contains("refused"), "{log}");
}

#[test]
fn bad_input() {
    let mut env = Env::new("input");
    env.start(current_uid());
    assert_eq!(env.client(&["get", "Bad Name"], b"").0, 1);
    assert_eq!(env.client(&["get"], b"").0, 64);
    assert_eq!(env.client(&["set", "github"], b"").0, 1, "empty secret");
    assert_eq!(env.client(&["set", "github"], &vec![b'x'; 16 * 1024 + 1]).0, 1, "too long");
    assert_eq!(env.client(&["set", "github"], &vec![b'x'; 16 * 1024]).0, 0, "limit fits");
}

#[test]
fn scan_finds_and_import_stores() {
    let mut env = Env::new("scan");
    env.start(current_uid());
    let token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    let proj = env.path("home/proj");
    fs::create_dir_all(&proj).unwrap();
    fs::create_dir_all(env.path("home/node_modules/x")).unwrap();
    fs::write(proj.join(".env"), format!("NODE_ENV=dev\nGITHUB_TOKEN={token}\n")).unwrap();
    fs::write(proj.join(".env.example"), format!("GITHUB_TOKEN={token}\n")).unwrap();
    fs::write(env.path("home/node_modules/x/.env"), format!("GITHUB_TOKEN={token}\n")).unwrap();
    fs::write(env.path("home/.npmrc"), "//registry.npmjs.org/:_authToken=npm_abcdefghijklmnop1234\n").unwrap();
    let home = env.path("home").to_string_lossy().into_owned();

    let (code, out, err) = env.client(&["scan", &home], b"");
    assert_eq!(code, 0, "{err}");
    assert_eq!(out.lines().count(), 2, "skips .env.example and node_modules:\n{out}");
    assert!(out.contains("proj/.env:2  GITHUB_TOKEN  ghp_…6789  -> github"), "{out}");
    assert!(out.contains(".npmrc:1") && out.contains("-> npm"), "{out}");
    assert!(!out.contains(token) && !err.contains(token), "never prints values");
    let (_, json, _) = env.client(&["scan", "--json", &home], b"");
    assert!(json.contains("\"line\":2,\"var\":\"GITHUB_TOKEN\",\"preview\":\"ghp_…6789\",\"name\":\"github\""), "{json}");

    let spec = format!("{}:2", proj.join(".env").display());
    let (code, _, err) = env.client(&["import", &spec], b"");
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("stored github") && err.contains("plain copy is still"), "{err}");
    assert_eq!(env.client(&["get", "github"], b"").1, token);
    let (code, _, err) = env.client(&["import", &spec], b"");
    assert_eq!(code, 1, "never overwrites");
    assert!(err.contains("github is already stored"), "{err}");
    let line1 = format!("{}:1", proj.join(".env").display());
    assert_eq!(env.client(&["import", &line1], b"").0, 1, "nothing on line 1");

    // Several at once: one prompt, one write.
    let npmrc = format!("{}:1", env.path("home/.npmrc").display());
    let before = read(&env.path("approvals")).lines().count();
    let (code, _, err) = env.client(&["import", &format!("{spec}=gh-work"), &npmrc], b"");
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("stored gh-work,npm"), "{err}");
    assert_eq!(read(&env.path("approvals")).lines().count(), before + 1, "one prompt for the batch");
    assert!(read(&env.path("approvals")).contains("dev.agent-keychain.write gh-work,npm"));
    assert_eq!(env.client(&["list"], b"").1, "gh-work\ngithub\nnpm\n");
    assert_eq!(env.client(&["get", "npm"], b"").1, "npm_abcdefghijklmnop1234");
    let (code, _, err) = env.client(&["import", &format!("{spec}=x"), &format!("{npmrc}=x")], b"");
    assert_eq!(code, 1);
    assert!(err.contains("both be named x"), "{err}");

    // Denied batch stores nothing.
    fs::write(env.path("deny"), "").unwrap();
    assert_eq!(env.client(&["import", &format!("{spec}=d1"), &format!("{npmrc}=d2")], b"").0, 2);
    fs::remove_file(env.path("deny")).unwrap();
    assert_eq!(env.client(&["list"], b"").1, "gh-work\ngithub\nnpm\n");
    assert!(read(&proj.join(".env")).contains(token), "file left as it was");
}

#[test]
fn skill_prints_agent_guide() {
    let out = Command::new(CLIENT).arg("skill").output().unwrap();
    assert!(out.status.success());
    let guide = String::from_utf8(out.stdout).unwrap();
    for want in ["agent-keychain get", "Exit codes", "Never print", "agent-keychain with"] {
        assert!(guide.contains(want), "guide lacks {want:?}");
    }
}

#[test]
fn help() {
    let run = |args: &[&str]| summarize(Command::new(CLIENT).args(args).output().unwrap());
    let (code, out, _) = run(&["--help"]);
    assert_eq!(code, 0);
    assert!(out.contains("AI agents: run `agent-keychain skill` first"), "{out}");
    for args in [&["help", "get"][..], &["get", "--help"], &["get", "-h"]] {
        let (code, out, _) = run(args);
        assert_eq!((code, out.starts_with("usage: agent-keychain get <name>")), (0, true), "{args:?}: {out}");
    }
    assert!(run(&["with", "--help"]).1.starts_with("usage: agent-keychain with"));
    assert!(run(&["help", "doctor"]).1.contains("Checks the install"));
    assert_eq!(run(&["help", "nope"]).0, 64);
}

#[test]
fn json_everywhere() {
    let mut env = Env::new("json");
    env.start(current_uid());
    assert_eq!(env.client(&["set", "x", "--json"], b"v1"), (0, "{\"stored\":[\"x\"]}\n".into(), String::new()));
    assert_eq!(env.client(&["--version", "--json"], b"").1, format!("{{\"version\":\"{}\"}}\n", env!("CARGO_PKG_VERSION")));
    assert_eq!(env.client(&["rm", "nope", "--json"], b""), (1, "{\"error\":\"no secret named nope\",\"code\":1}\n".into(), String::new()));
    assert_eq!(env.client(&["get", "x", "--json"], b"").0, 64, "get never wraps the value");
    fs::write(env.path("deny"), "").unwrap();
    assert_eq!(env.client(&["rm", "x", "--json"], b"").1, "{\"error\":\"denied\",\"code\":2}\n");
    fs::remove_file(env.path("deny")).unwrap();
    assert_eq!(env.client(&["rm", "x", "--json"], b"").1, "{\"removed\":\"x\"}\n");

    // doctor talks to this daemon; service and policy depend on the machine, so only
    // the socket and version checks are asserted.
    let (_, out, _) = env.client(&["doctor", "--json"], b"");
    assert!(out.contains("{\"check\":\"socket\",\"ok\":true"), "{out}");
    assert!(out.contains(&format!("{{\"check\":\"daemon\",\"ok\":true,\"detail\":\"{}\"}}", env!("CARGO_PKG_VERSION"))), "{out}");
    let (_, out, _) = env.client(&["doctor"], b"");
    assert!(out.lines().any(|l| l.starts_with("ok") && l.contains("daemon")), "{out}");
}

#[test]
fn version() {
    let want = env!("CARGO_PKG_VERSION");
    for (bin, flag) in [(CLIENT, "--version"), (CLIENT, "-V"), (DAEMON, "--version")] {
        let out = Command::new(bin).arg(flag).output().unwrap();
        assert!(out.status.success());
        let text = String::from_utf8(out.stdout).unwrap();
        assert!(text.trim_end().ends_with(want), "{text}");
    }
}

#[test]
fn gen_key_prints_32_random_bytes() {
    let a = Command::new(DAEMON).arg("--gen-key").output().unwrap();
    let b = Command::new(DAEMON).arg("--gen-key").output().unwrap();
    assert!(a.status.success());
    assert_eq!(a.stdout.len(), 32);
    assert_ne!(a.stdout, b.stdout);
}
