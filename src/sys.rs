//! Hand-written bindings to the few glibc and kernel interfaces this crate uses.
//!
//! Layouts match glibc on 64-bit Linux (x86_64 and aarch64).

#![allow(non_camel_case_types)]

use std::os::raw::{c_int, c_uint, c_void};

#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
compile_error!("agent-keychain supports 64-bit Linux only");

// AF_ALG, from <linux/if_alg.h> and <linux/socket.h>.
pub const AF_ALG: c_int = 38;
pub const SOL_ALG: c_int = 279;
pub const ALG_SET_KEY: c_int = 1;
pub const ALG_SET_IV: c_int = 2;
pub const ALG_SET_OP: c_int = 3;
pub const ALG_SET_AEAD_ASSOCLEN: c_int = 4;
pub const ALG_SET_AEAD_AUTHSIZE: c_int = 5;
pub const ALG_OP_DECRYPT: u32 = 0;
pub const ALG_OP_ENCRYPT: u32 = 1;

pub const SOCK_SEQPACKET: c_int = 5;
pub const SOCK_CLOEXEC: c_int = 0o2000000;
pub const SOL_SOCKET: c_int = 1;
pub const SO_PEERCRED: c_int = 17;

pub const EBADMSG: i32 = 74;
pub const PR_SET_DUMPABLE: c_int = 4;
pub const ECHO: u32 = 0o10;
pub const TCSANOW: c_int = 0;

#[repr(C)]
pub struct sockaddr_alg {
    pub salg_family: u16,
    pub salg_type: [u8; 14],
    pub salg_feat: u32,
    pub salg_mask: u32,
    pub salg_name: [u8; 64],
}

#[repr(C)]
pub struct iovec {
    pub iov_base: *mut c_void,
    pub iov_len: usize,
}

#[repr(C)]
pub struct msghdr {
    pub msg_name: *mut c_void,
    pub msg_namelen: u32,
    pub msg_iov: *mut iovec,
    pub msg_iovlen: usize,
    pub msg_control: *mut c_void,
    pub msg_controllen: usize,
    pub msg_flags: c_int,
}

#[repr(C)]
pub struct cmsghdr {
    pub cmsg_len: usize,
    pub cmsg_level: c_int,
    pub cmsg_type: c_int,
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
    pub fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
    pub fn bind(fd: c_int, addr: *const c_void, len: u32) -> c_int;
    pub fn accept(fd: c_int, addr: *mut c_void, len: *mut u32) -> c_int;
    pub fn setsockopt(fd: c_int, level: c_int, name: c_int, val: *const c_void, len: u32) -> c_int;
    pub fn getsockopt(fd: c_int, level: c_int, name: c_int, val: *mut c_void, len: *mut u32)
    -> c_int;
    pub fn sendmsg(fd: c_int, msg: *const msghdr, flags: c_int) -> isize;
    pub fn read(fd: c_int, buf: *mut c_void, n: usize) -> isize;
    pub fn getrandom(buf: *mut c_void, n: usize, flags: c_uint) -> isize;
    pub fn prctl(option: c_int, ...) -> c_int;
    pub fn getuid() -> u32;
    pub fn isatty(fd: c_int) -> c_int;
    pub fn tcgetattr(fd: c_int, t: *mut termios) -> c_int;
    pub fn tcsetattr(fd: c_int, action: c_int, t: *const termios) -> c_int;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts_match_glibc() {
        assert_eq!(size_of::<sockaddr_alg>(), 88);
        assert_eq!(size_of::<cmsghdr>(), 16);
        assert_eq!(size_of::<msghdr>(), 56);
        assert_eq!(size_of::<ucred>(), 12);
        assert_eq!(size_of::<termios>(), 60);
    }
}
