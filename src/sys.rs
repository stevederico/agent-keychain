//! Hand-written bindings to the few glibc interfaces this crate uses.
//!
//! Layouts match glibc on 64-bit Linux (x86_64 and aarch64).

#![allow(non_camel_case_types)]

use std::os::raw::{c_int, c_uint, c_void};

#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
compile_error!("agent-keychain supports 64-bit Linux only");

pub const SOL_SOCKET: c_int = 1;
pub const SO_PEERCRED: c_int = 17;
pub const SO_PEERPIDFD: c_int = 77;
pub const PR_SET_DUMPABLE: c_int = 4;
pub const ECHO: u32 = 0o10;
pub const TCSANOW: c_int = 0;
pub const SIGHUP: c_int = 1;
pub const SIGINT: c_int = 2;
pub const SIGQUIT: c_int = 3;
pub const SIGTERM: c_int = 15;
pub const SIG_DFL: sighandler_t = 0;
pub const POLLIN: i16 = 1;

/// A handler address, or SIG_DFL.
pub type sighandler_t = usize;

#[repr(C)]
pub struct pollfd {
    pub fd: c_int,
    pub events: i16,
    pub revents: i16,
}

#[repr(C)]
#[derive(Default)]
pub struct ucred {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct termios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line: u8,
    pub c_cc: [u8; 32],
    pub c_ispeed: u32,
    pub c_ospeed: u32,
}

unsafe extern "C" {
    pub fn getsockopt(fd: c_int, level: c_int, name: c_int, val: *mut c_void, len: *mut u32)
    -> c_int;
    pub fn getrandom(buf: *mut c_void, n: usize, flags: c_uint) -> isize;
    pub fn prctl(option: c_int, ...) -> c_int;
    pub fn getuid() -> u32;
    pub fn isatty(fd: c_int) -> c_int;
    pub fn tcgetattr(fd: c_int, t: *mut termios) -> c_int;
    pub fn tcsetattr(fd: c_int, action: c_int, t: *const termios) -> c_int;
    pub fn signal(sig: c_int, handler: sighandler_t) -> sighandler_t;
    pub fn raise(sig: c_int) -> c_int;
    pub fn poll(fds: *mut pollfd, nfds: u64, timeout: c_int) -> c_int;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts_match_glibc() {
        assert_eq!(size_of::<ucred>(), 12);
        assert_eq!(size_of::<termios>(), 60);
        assert_eq!(size_of::<pollfd>(), 8);
    }
}
