//! Who is on the other end of a socket, from the kernel.

use crate::sys;
use std::fs;
use std::io;
use std::os::fd::RawFd;

pub struct Peer {
    pub pid: i32,
    pub uid: u32,
}

pub fn current_uid() -> u32 {
    // SAFETY: getuid() takes no arguments and cannot fail.
    unsafe { sys::getuid() }
}

/// The connecting process's pid and uid (SO_PEERCRED), recorded by the kernel at connect().
pub fn peer_cred(fd: RawFd) -> io::Result<Peer> {
    let mut cred = sys::ucred::default();
    let mut len = size_of::<sys::ucred>() as u32;
    // SAFETY: `cred` is a writable ucred and `len` holds its size.
    let r = unsafe {
        sys::getsockopt(fd, sys::SOL_SOCKET, sys::SO_PEERCRED, (&raw mut cred).cast(), &mut len)
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    if cred.pid <= 0 {
        return Err(io::Error::other("peer has no pid"));
    }
    Ok(Peer { pid: cred.pid, uid: cred.uid })
}

/// (parent pid, start time in clock ticks) from /proc/<pid>/stat.
pub fn proc_stat(pid: i32) -> io::Result<(i32, u64)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    // The command name is in parentheses and may contain spaces; fields resume after the last ')'.
    let after = stat.rsplit_once(')').ok_or_else(|| io::Error::other("bad /proc stat"))?.1;
    let fields: Vec<&str> = after.split_whitespace().collect();
    // fields[0] is field 3 (state), so field 4 (ppid) is [1] and field 22 (starttime) is [19].
    let parse_err = || io::Error::other("bad /proc stat");
    let ppid = fields.get(1).and_then(|s| s.parse().ok()).ok_or_else(parse_err)?;
    let start = fields.get(19).and_then(|s| s.parse().ok()).ok_or_else(parse_err)?;
    Ok((ppid, start))
}

/// A best-effort "client <- parent <- grandparent" chain of command names.
/// Processes choose their own names, so this is a hint for the user, not proof.
pub fn describe_caller(pid: i32) -> String {
    let mut chain = Vec::new();
    let mut pid = pid;
    for _ in 0..4 {
        if pid <= 1 {
            break;
        }
        let comm = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_else(|_| "?".into());
        chain.push(sanitize(comm.trim_end()));
        match proc_stat(pid) {
            Ok((ppid, _)) => pid = ppid,
            Err(_) => break,
        }
    }
    if chain.is_empty() { "?".into() } else { chain.join(" <- ") }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' })
        .map(|c| if c == '"' { '\'' } else { c })
        .take(32)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_process() {
        let me = std::process::id() as i32;
        let (ppid, start) = proc_stat(me).unwrap();
        assert!(ppid > 0 && start > 0);
        assert!(!describe_caller(me).is_empty());
    }

    #[test]
    fn sanitizes() {
        assert_eq!(sanitize("a\"b\nc"), "a'b?c");
    }
}
