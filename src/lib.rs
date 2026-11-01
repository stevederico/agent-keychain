//! agent-keychain: a local keychain that gives AI agents a secret only after the user approves.
//! Std only, no crates. Crypto is the kernel's (AF_ALG); approval is polkit's.

pub mod crypto;
pub mod names;
pub mod peer;
pub mod proto;
pub mod sys;
pub mod time;
pub mod vault;
