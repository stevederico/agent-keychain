//! agent-keychain: a local keychain that gives AI agents a secret only after the user approves.
//! Std only, no crates. Crypto is XChaCha20-Poly1305 ported from libsodium; approval is polkit's.

pub mod crypto;
pub mod names;
pub mod peer;
pub mod proto;
pub mod scan;
pub mod sys;
pub mod time;
pub mod vault;
