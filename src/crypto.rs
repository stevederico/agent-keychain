//! XChaCha20-Poly1305 (IETF), ported line by line from libsodium 1.0.22:
//!
//! - ChaCha20:  src/libsodium/crypto_stream/chacha20/ref/chacha20_ref.c (D. J. Bernstein, public domain)
//! - HChaCha20: src/libsodium/crypto_core/hchacha20/core_hchacha20.c
//! - Poly1305:  src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna{.c,64.h}
//! - AEAD:      src/libsodium/crypto_aead/xchacha20poly1305/aead_xchacha20poly1305.c
//! - Verify:    src/libsodium/crypto_verify/verify.c
//!
//! Copyright (c) 2013-2026 Frank Denis <j at pureftpd dot org>
//!
//! Permission to use, copy, modify, and/or distribute this software for any
//! purpose with or without fee is hereby granted, provided that the above
//! copyright notice and this permission notice appear in all copies.
//!
//! THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
//! WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
//! MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
//! ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
//! WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
//! ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
//! OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use crate::sys;
use std::io;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{Ordering, compiler_fence};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

// ---------------------------------------------------------------------------
// Secret memory
// ---------------------------------------------------------------------------

/// Overwrites `buf` with zeros in a way the compiler may not remove (sodium_memzero).
pub fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, aligned, exclusive reference into `buf`.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

fn wipe_words<T: Copy + Default>(buf: &mut [T]) {
    for w in buf.iter_mut() {
        // SAFETY: `w` is a valid, aligned, exclusive reference into `buf`.
        unsafe { std::ptr::write_volatile(w, T::default()) };
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

/// A 32-byte vault key.
pub struct Key(SecretBytes);

impl Key {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Key> {
        if bytes.len() != KEY_LEN {
            return Err(invalid(format!("vault key must be {KEY_LEN} bytes, got {}", bytes.len())));
        }
        Ok(Key(SecretBytes::from_slice(bytes)))
    }

    #[cfg(test)]
    pub fn generate() -> io::Result<Key> {
        let mut k = SecretBytes::zeroed(KEY_LEN);
        random(&mut k)?;
        Ok(Key(k))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        (&*self.0).try_into().expect("key length is fixed")
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

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

// ---------------------------------------------------------------------------
// Public AEAD: XChaCha20-Poly1305 (crypto_aead_xchacha20poly1305_ietf_*)
// ---------------------------------------------------------------------------

/// Encrypts `plaintext`. Returns ciphertext followed by the 16-byte tag.
pub fn seal(key: &Key, nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let (mut k2, n2) = xchacha_subkey(key.as_bytes(), nonce);
    let out = ietf_seal(&k2, &n2, aad, plaintext);
    wipe(&mut k2);
    out
}

/// Authenticates, then decrypts `sealed` (ciphertext followed by tag).
pub fn open(key: &Key, nonce: &[u8; NONCE_LEN], aad: &[u8], sealed: &[u8]) -> io::Result<SecretBytes> {
    let (mut k2, n2) = xchacha_subkey(key.as_bytes(), nonce);
    let out = ietf_open(&k2, &n2, aad, sealed);
    wipe(&mut k2);
    out.ok_or_else(|| invalid("authentication failed: wrong key or tampered data"))
}

/// crypto_aead_xchacha20poly1305_ietf_encrypt_detached: k2 = HChaCha20(k, npub[0..16]),
/// npub2 = 4 zero bytes || npub[16..24].
fn xchacha_subkey(key: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> ([u8; 32], [u8; 12]) {
    let k2 = hchacha20(key, nonce[..16].try_into().unwrap());
    let mut n2 = [0u8; 12];
    n2[4..].copy_from_slice(&nonce[16..]);
    (k2, n2)
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 IETF construction (_encrypt_detached / _decrypt_detached)
// ---------------------------------------------------------------------------

const PAD0: [u8; 16] = [0; 16];

/// Largest message the 32-bit block counter allows, starting at block 1.
const MESSAGE_MAX: u64 = 64 * (u32::MAX as u64 - 1);

fn ietf_tag(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut block0 = [0u8; 64];
    chacha20_ietf_xor(key, nonce, 0, &mut block0);
    let mut poly = Poly1305::new(block0[..32].try_into().unwrap());
    wipe(&mut block0);

    poly.update(aad);
    poly.update(&PAD0[..(16 - aad.len() % 16) % 16]);
    poly.update(ct);
    poly.update(&PAD0[..(16 - ct.len() % 16) % 16]);
    poly.update(&(aad.len() as u64).to_le_bytes());
    poly.update(&(ct.len() as u64).to_le_bytes());
    poly.finish()
}

fn ietf_seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    assert!(plaintext.len() as u64 <= MESSAGE_MAX, "message too long for ChaCha20-Poly1305");
    let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN);
    out.extend_from_slice(plaintext);
    chacha20_ietf_xor(key, nonce, 1, &mut out);
    let tag = ietf_tag(key, nonce, aad, &out);
    out.extend_from_slice(&tag);
    out
}

fn ietf_open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], sealed: &[u8]) -> Option<SecretBytes> {
    if sealed.len() < TAG_LEN || (sealed.len() - TAG_LEN) as u64 > MESSAGE_MAX {
        return None;
    }
    let (ct, tag) = sealed.split_at(sealed.len() - TAG_LEN);
    let mut computed = ietf_tag(key, nonce, aad, ct);
    let ok = verify_16(&computed, tag.try_into().unwrap());
    wipe(&mut computed);
    if !ok {
        return None;
    }
    // Decrypt only after the tag checks out (libsodium's ACQUIRE_FENCE).
    compiler_fence(Ordering::Acquire);
    let mut pt = SecretBytes::from_slice(ct);
    chacha20_ietf_xor(key, nonce, 1, &mut pt);
    Some(pt)
}

/// Constant-time 16-byte comparison (crypto_verify_16): OR together every byte difference,
/// then test once, so timing does not depend on where the tags differ.
fn verify_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut d: u8 = 0;
    for i in 0..16 {
        d |= std::hint::black_box(a[i] ^ b[i]);
    }
    // SAFETY: reading a local through a valid pointer; volatile stops the compiler
    // from turning the loop above into an early exit.
    unsafe { std::ptr::read_volatile(&d) == 0 }
}

// ---------------------------------------------------------------------------
// ChaCha20 core (chacha20_ref.c, core_hchacha20.c)
// ---------------------------------------------------------------------------

const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[..4].try_into().unwrap())
}

fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[..8].try_into().unwrap())
}

#[inline(always)]
fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}

/// 20 rounds: 10 column + diagonal double rounds.
fn double_rounds(x: &mut [u32; 16]) {
    for _ in 0..10 {
        quarter_round(x, 0, 4, 8, 12);
        quarter_round(x, 1, 5, 9, 13);
        quarter_round(x, 2, 6, 10, 14);
        quarter_round(x, 3, 7, 11, 15);
        quarter_round(x, 0, 5, 10, 15);
        quarter_round(x, 1, 6, 11, 12);
        quarter_round(x, 2, 7, 8, 13);
        quarter_round(x, 3, 4, 9, 14);
    }
}

fn key_words(state: &mut [u32; 16], key: &[u8; 32]) {
    state[..4].copy_from_slice(&SIGMA);
    for i in 0..8 {
        state[4 + i] = le32(&key[4 * i..]);
    }
}

/// crypto_core_hchacha20 with the default constants: rounds without the final addition,
/// output words 0..4 and 12..16.
fn hchacha20(key: &[u8; 32], input: &[u8; 16]) -> [u8; 32] {
    let mut x = [0u32; 16];
    key_words(&mut x, key);
    for i in 0..4 {
        x[12 + i] = le32(&input[4 * i..]);
    }
    double_rounds(&mut x);

    let mut out = [0u8; 32];
    for i in 0..4 {
        out[4 * i..4 * i + 4].copy_from_slice(&x[i].to_le_bytes());
        out[16 + 4 * i..16 + 4 * i + 4].copy_from_slice(&x[12 + i].to_le_bytes());
    }
    wipe_words(&mut x);
    out
}

/// IETF ChaCha20 (32-bit counter, 96-bit nonce): XORs the keystream from block `counter` into `buf`.
fn chacha20_ietf_xor(key: &[u8; 32], nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
    let blocks = buf.len().div_ceil(64) as u64;
    assert!(counter as u64 + blocks <= u32::MAX as u64 + 1, "ChaCha20 block counter would wrap");

    let mut state = [0u32; 16];
    key_words(&mut state, key);
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = le32(&nonce[4 * i..]);
    }

    let mut x = [0u32; 16];
    let mut stream = [0u8; 64];
    for chunk in buf.chunks_mut(64) {
        x = state;
        double_rounds(&mut x);
        for i in 0..16 {
            stream[4 * i..4 * i + 4].copy_from_slice(&x[i].wrapping_add(state[i]).to_le_bytes());
        }
        for (b, k) in chunk.iter_mut().zip(stream.iter()) {
            *b ^= k;
        }
        state[12] = state[12].wrapping_add(1);
    }
    wipe_words(&mut state);
    wipe_words(&mut x);
    wipe(&mut stream);
}

// ---------------------------------------------------------------------------
// Poly1305, 64-bit limbs (poly1305_donna64.h, poly1305_donna.c)
// ---------------------------------------------------------------------------

const BLOCK: usize = 16;
const MASK44: u64 = 0xfff_ffff_ffff;
const MASK42: u64 = 0x3ff_ffff_ffff;

struct Poly1305 {
    r: [u64; 3],
    h: [u64; 3],
    pad: [u64; 2],
    leftover: usize,
    buffer: [u8; BLOCK],
    last: bool,
}

impl Poly1305 {
    fn new(key: &[u8; 32]) -> Self {
        // r &= 0xffffffc0ffffffc0ffffffc0fffffff
        let t0 = le64(&key[0..]);
        let t1 = le64(&key[8..]);
        Poly1305 {
            r: [t0 & 0xffc_0fff_ffff, ((t0 >> 44) | (t1 << 20)) & 0xfff_ffc0_ffff, (t1 >> 24) & 0x00f_ffff_fc0f],
            h: [0; 3],
            pad: [le64(&key[16..]), le64(&key[24..])],
            leftover: 0,
            buffer: [0; BLOCK],
            last: false,
        }
    }

    /// Processes whole 16-byte blocks of `m`.
    fn blocks(&mut self, m: &[u8]) {
        let hibit: u64 = if self.last { 0 } else { 1 << 40 }; // 1 << 128
        let [r0, r1, r2] = self.r;
        let [mut h0, mut h1, mut h2] = self.h;
        let s1 = r1 * (5 << 2);
        let s2 = r2 * (5 << 2);
        let mul = |a: u64, b: u64| a as u128 * b as u128;

        for block in m.as_chunks::<BLOCK>().0 {
            // h += m[i]
            let t0 = le64(&block[0..]);
            let t1 = le64(&block[8..]);
            h0 += t0 & MASK44;
            h1 += ((t0 >> 44) | (t1 << 20)) & MASK44;
            h2 += ((t1 >> 24) & MASK42) | hibit;

            // h *= r
            let d0 = mul(h0, r0) + mul(h1, s2) + mul(h2, s1);
            let mut d1 = mul(h0, r1) + mul(h1, r0) + mul(h2, s2);
            let mut d2 = mul(h0, r2) + mul(h1, r1) + mul(h2, r0);

            // (partial) h %= p
            let c = (d0 >> 44) as u64;
            h0 = d0 as u64 & MASK44;
            d1 += c as u128;
            let c = (d1 >> 44) as u64;
            h1 = d1 as u64 & MASK44;
            d2 += c as u128;
            let c = (d2 >> 42) as u64;
            h2 = d2 as u64 & MASK42;
            h0 += c * 5;
            let c = h0 >> 44;
            h0 &= MASK44;
            h1 += c;
        }
        self.h = [h0, h1, h2];
    }

    fn update(&mut self, mut m: &[u8]) {
        // handle leftover
        if self.leftover > 0 {
            let want = (BLOCK - self.leftover).min(m.len());
            self.buffer[self.leftover..self.leftover + want].copy_from_slice(&m[..want]);
            m = &m[want..];
            self.leftover += want;
            if self.leftover < BLOCK {
                return;
            }
            let buffer = self.buffer;
            self.blocks(&buffer);
            self.leftover = 0;
        }

        // process full blocks
        let full = m.len() & !(BLOCK - 1);
        if full > 0 {
            self.blocks(&m[..full]);
            m = &m[full..];
        }

        // store leftover
        if !m.is_empty() {
            self.buffer[self.leftover..self.leftover + m.len()].copy_from_slice(m);
            self.leftover += m.len();
        }
    }

    fn finish(mut self) -> [u8; 16] {
        // process the remaining block
        if self.leftover > 0 {
            let i = self.leftover;
            self.buffer[i] = 1;
            self.buffer[i + 1..].fill(0);
            self.last = true;
            let buffer = self.buffer;
            self.blocks(&buffer);
        }

        // fully carry h
        let [mut h0, mut h1, mut h2] = self.h;
        let mut c = h1 >> 44;
        h1 &= MASK44;
        h2 += c;
        c = h2 >> 42;
        h2 &= MASK42;
        h0 += c * 5;
        c = h0 >> 44;
        h0 &= MASK44;
        h1 += c;
        c = h1 >> 44;
        h1 &= MASK44;
        h2 += c;
        c = h2 >> 42;
        h2 &= MASK42;
        h0 += c * 5;
        c = h0 >> 44;
        h0 &= MASK44;
        h1 += c;

        // compute h + -p
        let mut g0 = h0 + 5;
        c = g0 >> 44;
        g0 &= MASK44;
        let mut g1 = h1 + c;
        c = g1 >> 44;
        g1 &= MASK44;
        let mut g2 = (h2 + c).wrapping_sub(1 << 42);

        // select h if h < p, or h + -p if h >= p (branch-free)
        let mut mask = (g2 >> 63).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        mask = !mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;

        // h = (h + pad)
        let [t0, t1] = self.pad;
        h0 += t0 & MASK44;
        c = h0 >> 44;
        h0 &= MASK44;
        h1 += (((t0 >> 44) | (t1 << 20)) & MASK44) + c;
        c = h1 >> 44;
        h1 &= MASK44;
        h2 += ((t1 >> 24) & MASK42) + c;
        h2 &= MASK42;

        // mac = h % (2^128)
        let lo = h0 | (h1 << 44);
        let hi = (h1 >> 20) | (h2 << 24);
        let mut mac = [0u8; 16];
        mac[..8].copy_from_slice(&lo.to_le_bytes());
        mac[8..].copy_from_slice(&hi.to_le_bytes());

        // zero out the state
        wipe_words(&mut self.r);
        wipe_words(&mut self.h);
        wipe_words(&mut self.pad);
        wipe(&mut self.buffer);
        mac
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    const SUNSCREEN: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    // RFC 8439 2.4.2
    #[test]
    fn chacha20_rfc8439() {
        let key: [u8; 32] = (0..32).collect::<Vec<u8>>().try_into().unwrap();
        let nonce: [u8; 12] = hex("000000000000004a00000000").try_into().unwrap();
        let mut buf = SUNSCREEN.to_vec();
        chacha20_ietf_xor(&key, &nonce, 1, &mut buf);
        assert_eq!(&buf[..16], &hex("6e2e359a2568f98041ba0728dd0d6981")[..]);
        assert_eq!(&buf[buf.len() - 2..], &hex("874d")[..]);
    }

    // RFC 8439 2.5.2
    #[test]
    fn poly1305_rfc8439() {
        let key: [u8; 32] =
            hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b").try_into().unwrap();
        let mut p = Poly1305::new(&key);
        p.update(b"Cryptographic Forum Research Group");
        assert_eq!(&p.finish()[..], &hex("a8061dc1305136c6c22b8baf0c0127a9")[..]);
    }

    // RFC 8439 2.8.2
    #[test]
    fn aead_rfc8439() {
        let key: [u8; 32] = (0x80..=0x9f).collect::<Vec<u8>>().try_into().unwrap();
        let nonce: [u8; 12] = hex("070000004041424344454647").try_into().unwrap();
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let sealed = ietf_seal(&key, &nonce, &aad, SUNSCREEN);
        assert_eq!(&sealed[..16], &hex("d31a8d34648e60db7b86afbc53ef7ec2")[..]);
        assert_eq!(&sealed[SUNSCREEN.len()..], &hex("1ae10b594f09e26a7e902ecbd0600691")[..]);
        assert_eq!(&ietf_open(&key, &nonce, &aad, &sealed).unwrap()[..], SUNSCREEN);
    }

    // draft-irtf-cfrg-xchacha 2.2.1
    #[test]
    fn hchacha20_draft() {
        let key: [u8; 32] = (0..32).collect::<Vec<u8>>().try_into().unwrap();
        let input: [u8; 16] = hex("000000090000004a0000000031415927").try_into().unwrap();
        assert_eq!(
            &hchacha20(&key, &input)[..],
            &hex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")[..]
        );
    }

    // draft-irtf-cfrg-xchacha A.3.1
    #[test]
    fn xchacha20poly1305_draft() {
        let key = Key::from_bytes(&(0x80..=0x9f).collect::<Vec<u8>>()).unwrap();
        let nonce: [u8; 24] = (0x40..0x58).collect::<Vec<u8>>().try_into().unwrap();
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let sealed = seal(&key, &nonce, &aad, SUNSCREEN);
        assert_eq!(&sealed[..16], &hex("bd6d179d3e83d43b9576579493c0e939")[..]);
        assert_eq!(&sealed[SUNSCREEN.len()..], &hex("c0875924c1c7987947deafd8780acf49")[..]);
        assert_eq!(&open(&key, &nonce, &aad, &sealed).unwrap()[..], SUNSCREEN);
    }

    #[test]
    fn tampering_is_rejected() {
        let key = Key::generate().unwrap();
        let nonce = [7u8; 24];
        let mut sealed = seal(&key, &nonce, b"name", b"token");
        assert!(open(&key, &nonce, b"other", &sealed).is_err(), "wrong aad");
        assert!(open(&Key::generate().unwrap(), &nonce, b"name", &sealed).is_err(), "wrong key");
        assert!(open(&key, &[8u8; 24], b"name", &sealed).is_err(), "wrong nonce");
        assert!(open(&key, &nonce, b"name", &sealed[..10]).is_err(), "truncated");
        for i in 0..sealed.len() {
            sealed[i] ^= 1;
            assert!(open(&key, &nonce, b"name", &sealed).is_err(), "flipped byte {i}");
            sealed[i] ^= 1;
        }
        assert_eq!(&open(&key, &nonce, b"name", &sealed).unwrap()[..], b"token");
    }

    #[test]
    fn verify_16_compares() {
        assert!(verify_16(&[3; 16], &[3; 16]));
        let mut b = [3u8; 16];
        b[15] = 4;
        assert!(!verify_16(&[3; 16], &b));
    }

    #[test]
    fn wipe_zeroes() {
        let mut v = vec![1u8; 8];
        wipe(&mut v);
        assert_eq!(v, [0; 8]);
    }

    /// Differential tests against the system libsodium. Test builds only: the shipped
    /// binaries never link it.
    mod vs_libsodium {
        use super::super::*;
        use std::os::raw::{c_int, c_uchar, c_ulonglong};

        #[link(name = "sodium")]
        unsafe extern "C" {
            fn sodium_init() -> c_int;
            fn crypto_aead_xchacha20poly1305_ietf_encrypt(
                c: *mut c_uchar,
                clen: *mut c_ulonglong,
                m: *const c_uchar,
                mlen: c_ulonglong,
                ad: *const c_uchar,
                adlen: c_ulonglong,
                nsec: *const c_uchar,
                npub: *const c_uchar,
                k: *const c_uchar,
            ) -> c_int;
            fn crypto_onetimeauth_poly1305(
                out: *mut c_uchar,
                m: *const c_uchar,
                mlen: c_ulonglong,
                k: *const c_uchar,
            ) -> c_int;
            fn crypto_core_hchacha20(
                out: *mut c_uchar,
                input: *const c_uchar,
                k: *const c_uchar,
                c: *const c_uchar,
            ) -> c_int;
        }

        fn init() {
            // SAFETY: sodium_init is thread-safe and idempotent.
            assert!(unsafe { sodium_init() } >= 0);
        }

        fn rand_vec(len: usize) -> Vec<u8> {
            let mut v = vec![0u8; len];
            random(&mut v).unwrap();
            v
        }

        fn sodium_seal(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], m: &[u8]) -> Vec<u8> {
            let mut out = vec![0u8; m.len() + TAG_LEN];
            let mut clen = 0;
            // SAFETY: buffers are sized as libsodium documents; nsec must be null.
            let r = unsafe {
                crypto_aead_xchacha20poly1305_ietf_encrypt(
                    out.as_mut_ptr(),
                    &mut clen,
                    m.as_ptr(),
                    m.len() as u64,
                    aad.as_ptr(),
                    aad.len() as u64,
                    std::ptr::null(),
                    nonce.as_ptr(),
                    key.as_ptr(),
                )
            };
            assert_eq!((r, clen as usize), (0, out.len()));
            out
        }

        #[test]
        fn aead_matches() {
            init();
            // Every length from 0 to 300 covers all Poly1305 leftover and padding paths.
            for len in 0..=300 {
                for aad_len in [0, 1, 15, 16, 17, len % 40] {
                    let key = Key::from_bytes(&rand_vec(32)).unwrap();
                    let nonce: [u8; 24] = rand_vec(24).try_into().unwrap();
                    let aad = rand_vec(aad_len);
                    let m = rand_vec(len);
                    let ours = seal(&key, &nonce, &aad, &m);
                    assert_eq!(ours, sodium_seal(key.as_bytes(), &nonce, &aad, &m), "len {len} aad {aad_len}");
                    assert_eq!(&open(&key, &nonce, &aad, &ours).unwrap()[..], &m[..]);
                }
            }
            // Multi-block messages up to the vault's 16 KiB limit.
            for len in [1023, 4096, 16 * 1024] {
                let key = Key::from_bytes(&rand_vec(32)).unwrap();
                let nonce: [u8; 24] = rand_vec(24).try_into().unwrap();
                let m = rand_vec(len);
                assert_eq!(seal(&key, &nonce, b"ad", &m), sodium_seal(key.as_bytes(), &nonce, b"ad", &m));
            }
        }

        #[test]
        fn poly1305_matches() {
            init();
            for len in 0..=400 {
                let key: [u8; 32] = rand_vec(32).try_into().unwrap();
                let m = rand_vec(len);
                let mut theirs = [0u8; 16];
                // SAFETY: out is 16 bytes, key 32, m `len`.
                unsafe { crypto_onetimeauth_poly1305(theirs.as_mut_ptr(), m.as_ptr(), len as u64, key.as_ptr()) };

                let mut whole = Poly1305::new(&key);
                whole.update(&m);
                assert_eq!(whole.finish(), theirs, "len {len}");

                // Same result when fed in uneven pieces.
                let mut pieces = Poly1305::new(&key);
                for chunk in m.chunks(1 + len % 7) {
                    pieces.update(chunk);
                }
                assert_eq!(pieces.finish(), theirs, "chunked len {len}");
            }
            // Edge keys: all ones stress the clamping and carries.
            for key in [[0xffu8; 32], [0u8; 32]] {
                let m = [0xffu8; 64];
                let mut theirs = [0u8; 16];
                // SAFETY: as above.
                unsafe { crypto_onetimeauth_poly1305(theirs.as_mut_ptr(), m.as_ptr(), 64, key.as_ptr()) };
                let mut p = Poly1305::new(&key);
                p.update(&m);
                assert_eq!(p.finish(), theirs);
            }
        }

        #[test]
        fn hchacha20_matches() {
            init();
            for _ in 0..200 {
                let key: [u8; 32] = rand_vec(32).try_into().unwrap();
                let input: [u8; 16] = rand_vec(16).try_into().unwrap();
                let mut theirs = [0u8; 32];
                // SAFETY: out 32, input 16, key 32; null constants means the default sigma.
                unsafe {
                    crypto_core_hchacha20(theirs.as_mut_ptr(), input.as_ptr(), key.as_ptr(), std::ptr::null())
                };
                assert_eq!(hchacha20(&key, &input), theirs);
            }
        }
    }
}
