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
fn run_hides_other_processes() {
    if !Path::new("/usr/bin/bwrap").exists() {
        eprintln!("skipped: no /usr/bin/bwrap");
        return;
    }
    let mut env = Env::new("run");
    env.start(current_uid());
    assert_eq!(env.client(&["set", "github"], b"tok").0, 0);

    let daemon = env.daemon.as_ref().unwrap().id();
    let script = format!("echo $$; [ -e /proc/{daemon} ] && echo daemon visible; true");
    let (code, out, err) = env.client(&["run", "--", "sh", "-c", &script], b"");
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, "2\n", "pid 2 under bwrap, nothing else in sight");

    // Secrets still work from inside.
    let (code, out, err) = env.client(&["run", CLIENT, "get", "github"], b"");
    assert_eq!((code, out.as_str()), (0, "tok"), "{err}");
    assert_eq!(env.client(&["run"], b"").0, 64);
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
fn gen_key_prints_32_random_bytes() {
    let a = Command::new(DAEMON).arg("--gen-key").output().unwrap();
    let b = Command::new(DAEMON).arg("--gen-key").output().unwrap();
    assert!(a.status.success());
    assert_eq!(a.stdout.len(), 32);
    assert_ne!(a.stdout, b.stdout);
}
