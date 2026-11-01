//! Who is on the other end of a socket, from the kernel.

use crate::sys;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

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

/// A pidfd for the connecting process (SO_PEERPIDFD). Unlike its pid, it can never
/// come to mean a different process.
pub fn peer_pidfd(fd: RawFd) -> io::Result<OwnedFd> {
    let mut pidfd: i32 = -1;
    let mut len = size_of::<i32>() as u32;
    // SAFETY: `pidfd` is a writable int and `len` holds its size.
    let r = unsafe {
        sys::getsockopt(fd, sys::SOL_SOCKET, sys::SO_PEERPIDFD, (&raw mut pidfd).cast(), &mut len)
    };
    if r < 0 || pidfd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel just handed us this descriptor; we are its only owner.
    Ok(unsafe { OwnedFd::from_raw_fd(pidfd) })
}

/// Whether the process behind a pidfd still holds its pid (running or not yet reaped),
/// so that pid cannot have been reused.
pub fn alive(pidfd: &OwnedFd) -> bool {
    // SAFETY: signal 0 only checks; no pointer is passed.
    unsafe { sys::pidfd_send_signal(pidfd.as_raw_fd(), 0, std::ptr::null_mut(), 0) == 0 }
}

/// (pid, start time) for `pid` and each ancestor below init, nearest first.
/// Parent links come from the kernel, so a process cannot claim another parent.
pub fn ancestry(pid: i32) -> io::Result<Vec<(i32, u64)>> {
    let mut chain = Vec::new();
    let mut pid = pid;
    while pid > 1 && chain.len() < 64 {
        let (ppid, start) = proc_stat(pid)?;
        chain.push((pid, start));
        pid = ppid;
    }
    Ok(chain)
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
    fn ancestry_starts_with_self() {
        let me = std::process::id() as i32;
        let chain = ancestry(me).unwrap();
        assert_eq!(chain[0], (me, proc_stat(me).unwrap().1));
        assert!(chain.iter().all(|&(p, _)| p > 1));
        assert_eq!(chain, ancestry(me).unwrap(), "stable while nothing exits");
    }

    #[test]
    fn sanitizes() {
        assert_eq!(sanitize("a\"b\nc"), "a'b?c");
    }
}
