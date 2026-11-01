//! ChaCha20-Poly1305 through the kernel's crypto API (AF_ALG). No cipher code lives here:
//! this module only frames requests to the kernel and reads its answers.

use crate::sys;
use std::io;
use std::ops::{Deref, DerefMut};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::raw::c_int;
use std::ptr::null_mut;
use std::sync::atomic::{Ordering, compiler_fence};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

const ALG_TYPE: &[u8] = b"aead";
const ALG_NAME: &[u8] = b"rfc7539(chacha20,poly1305)";

/// Overwrites `buf` with zeros in a way the compiler may not remove.
pub fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, aligned, exclusive reference into `buf`.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Fixed-size bytes that are wiped on drop. Never grows, so no stale copies are left by reallocation.
pub struct SecretBytes(Box<[u8]>);

impl SecretBytes {
    pub fn zeroed(len: usize) -> Self {
        Self(vec![0u8; len].into_boxed_slice())
    }

    pub fn from_slice(data: &[u8]) -> Self {
        let mut s = Self::zeroed(data.len());
        s.0.copy_from_slice(data);
        s
    }

    /// Copies `v` into exact-size storage and wipes `v`, including its spare capacity.
    pub fn from_vec(mut v: Vec<u8>) -> Self {
        let s = Self::from_slice(&v);
        let cap = v.capacity();
        v.resize(cap, 0);
        wipe(&mut v);
        s
    }
}

impl Deref for SecretBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl DerefMut for SecretBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes({} bytes)", self.0.len())
    }
}

/// A 32-byte vault key.
pub struct Key(SecretBytes);

impl Key {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Key> {
        if bytes.len() != KEY_LEN {
            return Err(invalid(format!("vault key must be {KEY_LEN} bytes, got {}", bytes.len())));
        }
        Ok(Key(SecretBytes::from_slice(bytes)))
    }

    pub fn generate() -> io::Result<Key> {
        let mut k = SecretBytes::zeroed(KEY_LEN);
        random(&mut k)?;
        Ok(Key(k))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Fills `buf` from the kernel's CSPRNG (getrandom(2)).
pub fn random(buf: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let rest = &mut buf[filled..];
        // SAFETY: the pointer and length describe the unfilled tail of `buf`.
        let n = unsafe { sys::getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        filled += n as usize;
    }
    Ok(())
}

/// Encrypts `plaintext`. Returns ciphertext followed by the 16-byte tag.
pub fn seal(key: &Key, nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> io::Result<Vec<u8>> {
    let out_len = aad.len() + plaintext.len() + TAG_LEN;
    let out = aead(key, sys::ALG_OP_ENCRYPT, nonce, aad, plaintext, out_len)?;
    if out.len() != plaintext.len() + TAG_LEN {
        return Err(io::Error::other("kernel crypto returned an unexpected length"));
    }
    Ok(out.to_vec())
}

/// Decrypts and authenticates `sealed` (ciphertext followed by tag).
pub fn open(key: &Key, nonce: &[u8; NONCE_LEN], aad: &[u8], sealed: &[u8]) -> io::Result<SecretBytes> {
    if sealed.len() < TAG_LEN {
        return Err(invalid("sealed data shorter than its tag"));
    }
    let out = aead(key, sys::ALG_OP_DECRYPT, nonce, aad, sealed, aad.len() + sealed.len())?;
    if out.len() != sealed.len() - TAG_LEN {
        return Err(io::Error::other("kernel crypto returned an unexpected length"));
    }
    Ok(out)
}

fn cvt(r: c_int) -> io::Result<c_int> {
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(r) }
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Opens a kernel transform socket bound to ChaCha20-Poly1305 with `key` set.
fn transform(key: &Key) -> io::Result<OwnedFd> {
    // SAFETY: plain syscall with no pointer arguments.
    let fd = cvt(unsafe { sys::socket(sys::AF_ALG, sys::SOCK_SEQPACKET | sys::SOCK_CLOEXEC, 0) })?;
    // SAFETY: `fd` was just returned by socket() and nothing else owns it.
    let tfm = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut addr = sys::sockaddr_alg {
        salg_family: sys::AF_ALG as u16,
        salg_type: [0; 14],
        salg_feat: 0,
        salg_mask: 0,
        salg_name: [0; 64],
    };
    addr.salg_type[..ALG_TYPE.len()].copy_from_slice(ALG_TYPE);
    addr.salg_name[..ALG_NAME.len()].copy_from_slice(ALG_NAME);
    // SAFETY: `addr` is a fully initialized sockaddr_alg and the length is its exact size.
    let bound = unsafe {
        sys::bind(fd, (&raw const addr).cast(), size_of::<sys::sockaddr_alg>() as u32)
    };
    if bound < 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(
            e.kind(),
            format!("kernel has no rfc7539(chacha20,poly1305) ({e}); load algif_aead and chacha20poly1305"),
        ));
    }

    // SAFETY: the key buffer is KEY_LEN readable bytes.
    cvt(unsafe {
        sys::setsockopt(fd, sys::SOL_ALG, sys::ALG_SET_KEY, key.as_bytes().as_ptr().cast(), KEY_LEN as u32)
    })?;
    // SAFETY: ALG_SET_AEAD_AUTHSIZE takes the tag length as optlen and a null optval.
    cvt(unsafe {
        sys::setsockopt(fd, sys::SOL_ALG, sys::ALG_SET_AEAD_AUTHSIZE, std::ptr::null(), TAG_LEN as u32)
    })?;
    Ok(tfm)
}

const CMSG_HDR: usize = size_of::<sys::cmsghdr>();
// Three control messages: op (4 bytes), iv (4 + 12 bytes), assoclen (4 bytes), each padded to 8.
const CONTROL_LEN: usize = (CMSG_HDR + 8) + (CMSG_HDR + 16) + (CMSG_HDR + 8);

const fn align8(n: usize) -> usize {
    (n + 7) & !7
}

/// Writes one cmsghdr plus data at `off` and returns the offset of the next one.
fn put_cmsg(buf: &mut [u8], off: usize, ty: c_int, data: &[u8]) -> usize {
    let len = CMSG_HDR + data.len();
    buf[off..off + 8].copy_from_slice(&len.to_ne_bytes());
    buf[off + 8..off + 12].copy_from_slice(&sys::SOL_ALG.to_ne_bytes());
    buf[off + 12..off + 16].copy_from_slice(&ty.to_ne_bytes());
    buf[off + CMSG_HDR..off + CMSG_HDR + data.len()].copy_from_slice(data);
    off + CMSG_HDR + align8(data.len())
}

/// Runs one AEAD operation. The kernel reads `aad || input` and writes `aad || output`;
/// this returns `output`.
fn aead(
    key: &Key,
    op: u32,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    input: &[u8],
    out_len: usize,
) -> io::Result<SecretBytes> {
    let tfm = transform(key)?;
    // SAFETY: `tfm` is a bound AF_ALG socket; null address arguments are allowed.
    let opfd = cvt(unsafe { sys::accept(tfm.as_raw_fd(), null_mut(), null_mut()) })?;
    // SAFETY: `opfd` was just returned by accept() and nothing else owns it.
    let opfd = unsafe { OwnedFd::from_raw_fd(opfd) };

    let mut data = SecretBytes::zeroed(aad.len() + input.len());
    data[..aad.len()].copy_from_slice(aad);
    data[aad.len()..].copy_from_slice(input);

    // struct af_alg_iv { u32 ivlen; u8 iv[]; }
    let mut iv = [0u8; 4 + NONCE_LEN];
    iv[..4].copy_from_slice(&(NONCE_LEN as u32).to_ne_bytes());
    iv[4..].copy_from_slice(nonce);

    // u64 storage keeps the control buffer 8-byte aligned, as cmsghdr requires.
    let mut control = [0u64; CONTROL_LEN / 8];
    {
        // SAFETY: viewing the u64 array as bytes; u8 has no alignment or validity requirements.
        let bytes =
            unsafe { std::slice::from_raw_parts_mut(control.as_mut_ptr().cast::<u8>(), CONTROL_LEN) };
        let off = put_cmsg(bytes, 0, sys::ALG_SET_OP, &op.to_ne_bytes());
        let off = put_cmsg(bytes, off, sys::ALG_SET_IV, &iv);
        let end = put_cmsg(bytes, off, sys::ALG_SET_AEAD_ASSOCLEN, &(aad.len() as u32).to_ne_bytes());
        debug_assert_eq!(end, CONTROL_LEN);
    }

    let mut iov = sys::iovec { iov_base: data.as_mut_ptr().cast(), iov_len: data.len() };
    let msg = sys::msghdr {
        msg_name: null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr().cast(),
        msg_controllen: CONTROL_LEN,
        msg_flags: 0,
    };
    // SAFETY: `msg` points at live buffers (`iov` -> `data`, `control`) for the whole call.
    let sent = unsafe { sys::sendmsg(opfd.as_raw_fd(), &msg, 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    if sent as usize != data.len() {
        return Err(io::Error::other("short write to kernel crypto"));
    }

    let mut out = SecretBytes::zeroed(out_len);
    // SAFETY: `out` is `out_len` writable bytes.
    let n = unsafe { sys::read(opfd.as_raw_fd(), out.as_mut_ptr().cast(), out.len()) };
    if n < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(sys::EBADMSG) {
            return Err(invalid("authentication failed: wrong key or tampered data"));
        }
        return Err(e);
    }
    let n = n as usize;
    if n < aad.len() || n > out.len() {
        return Err(io::Error::other("short read from kernel crypto"));
    }
    Ok(SecretBytes::from_slice(&out[aad.len()..n]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    // RFC 8439 section 2.8.2.
    #[test]
    fn rfc8439_vector() {
        let key = Key::from_bytes(&(0x80..=0x9f).collect::<Vec<u8>>()).unwrap();
        let nonce: [u8; 12] = hex("07000000 4041424344454647").try_into().unwrap();
        let aad = hex("50515253 c0c1c2c3c4c5c6c7");
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let sealed = seal(&key, &nonce, &aad, pt).unwrap();
        assert_eq!(sealed.len(), pt.len() + TAG_LEN);
        assert_eq!(&sealed[..16], &hex("d31a8d34648e60db7b86afbc53ef7ec2")[..]);
        assert_eq!(&sealed[pt.len()..], &hex("1ae10b594f09e26a7e902ecbd0600691")[..]);

        let opened = open(&key, &nonce, &aad, &sealed).unwrap();
        assert_eq!(&opened[..], &pt[..]);
    }

    #[test]
    fn tampering_is_rejected() {
        let key = Key::generate().unwrap();
        let nonce = [7u8; 12];
        let mut sealed = seal(&key, &nonce, b"name", b"token").unwrap();

        assert!(open(&key, &nonce, b"other", &sealed).is_err(), "wrong aad");
        assert!(open(&Key::generate().unwrap(), &nonce, b"name", &sealed).is_err(), "wrong key");
        sealed[0] ^= 1;
        assert!(open(&key, &nonce, b"name", &sealed).is_err(), "flipped bit");
    }

    #[test]
    fn empty_aad_and_random() {
        let key = Key::generate().unwrap();
        let mut nonce = [0u8; 12];
        random(&mut nonce).unwrap();
        let sealed = seal(&key, &nonce, b"", b"x").unwrap();
        assert_eq!(&open(&key, &nonce, b"", &sealed).unwrap()[..], b"x");
    }

    #[test]
    fn wipe_zeroes() {
        let mut v = vec![1u8; 8];
        wipe(&mut v);
        assert_eq!(v, [0; 8]);
    }
}
