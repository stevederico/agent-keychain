//! The vault file: named secrets, each sealed with the vault key.
//!
//! Format: `AKC1`, then per entry `u16 name_len | name | 12-byte nonce | u32 sealed_len | sealed`,
//! little-endian. The AEAD associated data binds each entry to its name.

use crate::crypto::{self, Key, NONCE_LEN, SecretBytes, TAG_LEN};
use crate::names::valid_name;
use crate::proto::MAX_SECRET;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

const MAGIC: &[u8; 4] = b"AKC1";
const AAD_PREFIX: &[u8] = b"agent-keychain:v1:";

#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub nonce: [u8; NONCE_LEN],
    pub sealed: Vec<u8>,
}

pub struct Vault {
    path: PathBuf,
    key: Key,
    entries: BTreeMap<String, Entry>,
}

impl Vault {
    /// Loads the vault at `path` (empty if missing) and checks every entry opens with `key`.
    pub fn open(path: PathBuf, key: Key) -> io::Result<Vault> {
        let entries = match fs::read(&path) {
            Ok(bytes) => decode(&bytes)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e),
        };
        let vault = Vault { path, key, entries };
        for name in vault.entries.keys() {
            vault.get(name).map_err(|e| io::Error::new(e.kind(), format!("entry {name}: {e}")))?;
        }
        Ok(vault)
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    pub fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    pub fn get(&self, name: &str) -> io::Result<Option<SecretBytes>> {
        match self.entries.get(name) {
            None => Ok(None),
            Some(e) => crypto::open(&self.key, &e.nonce, &aad(name), &e.sealed).map(Some),
        }
    }

    pub fn set(&mut self, name: &str, value: &[u8]) -> io::Result<()> {
        let mut nonce = [0u8; NONCE_LEN];
        crypto::random(&mut nonce)?;
        let sealed = crypto::seal(&self.key, &nonce, &aad(name), value);
        let old = self.entries.insert(name.to_string(), Entry { nonce, sealed });
        if let Err(e) = self.save() {
            match old {
                Some(o) => self.entries.insert(name.to_string(), o),
                None => self.entries.remove(name),
            };
            return Err(e);
        }
        Ok(())
    }

    /// Returns false when there was no such entry.
    pub fn remove(&mut self, name: &str) -> io::Result<bool> {
        let Some(old) = self.entries.remove(name) else { return Ok(false) };
        if let Err(e) = self.save() {
            self.entries.insert(name.to_string(), old);
            return Err(e);
        }
        Ok(true)
    }

    /// Writes a temp file, fsyncs it, renames it over the vault, then fsyncs the directory.
    fn save(&self) -> io::Result<()> {
        let tmp = self.path.with_extension("tmp");
        {
            let mut f =
                OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
            f.write_all(&encode(&self.entries))?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        if let Some(dir) = self.path.parent() {
            File::open(dir)?.sync_all()?;
        }
        Ok(())
    }
}

fn aad(name: &str) -> Vec<u8> {
    [AAD_PREFIX, name.as_bytes()].concat()
}

pub fn encode(entries: &BTreeMap<String, Entry>) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    for (name, e) in entries {
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&e.nonce);
        out.extend_from_slice(&(e.sealed.len() as u32).to_le_bytes());
        out.extend_from_slice(&e.sealed);
    }
    out
}

fn bad(m: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("vault file: {m}"))
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(bad("truncated"));
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
}

pub fn decode(bytes: &[u8]) -> io::Result<BTreeMap<String, Entry>> {
    let mut r = Reader(bytes.strip_prefix(MAGIC).ok_or_else(|| bad("not an agent-keychain vault"))?);
    let mut entries = BTreeMap::new();
    while !r.0.is_empty() {
        let name_len = u16::from_le_bytes(r.take(2)?.try_into().unwrap()) as usize;
        let name = std::str::from_utf8(r.take(name_len)?).map_err(|_| bad("name is not utf-8"))?;
        if !valid_name(name) {
            return Err(bad("invalid name"));
        }
        let nonce: [u8; NONCE_LEN] = r.take(NONCE_LEN)?.try_into().unwrap();
        let sealed_len = u32::from_le_bytes(r.take(4)?.try_into().unwrap()) as usize;
        if !(TAG_LEN..=MAX_SECRET + TAG_LEN).contains(&sealed_len) {
            return Err(bad("bad entry length"));
        }
        let sealed = r.take(sealed_len)?.to_vec();
        if entries.insert(name.to_string(), Entry { nonce, sealed }).is_some() {
            return Err(bad("duplicate name"));
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("akc-vault-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir.join("vault")
    }

    fn key(b: u8) -> Key {
        Key::from_bytes(&[b; 32]).unwrap()
    }

    #[test]
    fn set_get_remove_persist() {
        let path = temp_path("persist");
        let mut v = Vault::open(path.clone(), key(1)).unwrap();
        v.set("github", b"ghp_secret").unwrap();
        v.set("stripe", b"sk_test").unwrap();
        assert_eq!(&v.get("github").unwrap().unwrap()[..], b"ghp_secret");
        assert!(v.remove("stripe").unwrap());
        assert!(!v.remove("stripe").unwrap());

        let raw = fs::read(&path).unwrap();
        assert!(!raw.windows(10).any(|w| w == b"ghp_secret"), "plaintext on disk");

        let v = Vault::open(path.clone(), key(1)).unwrap();
        assert_eq!(v.names().collect::<Vec<_>>(), ["github"]);
        assert_eq!(&v.get("github").unwrap().unwrap()[..], b"ghp_secret");

        assert!(Vault::open(path, key(2)).is_err(), "wrong key must fail to open");
    }

    #[test]
    fn swapped_entries_fail() {
        // Moving one entry's ciphertext under another name must not decrypt.
        let path = temp_path("swap");
        let mut v = Vault::open(path.clone(), key(3)).unwrap();
        v.set("aaa", b"one").unwrap();
        v.set("bbb", b"two").unwrap();
        let mut entries = decode(&fs::read(&path).unwrap()).unwrap();
        let a = entries["aaa"].clone();
        entries.insert("bbb".into(), a);
        fs::write(&path, encode(&entries)).unwrap();
        assert!(Vault::open(path, key(3)).is_err());
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode(b"nope").is_err());
        assert!(decode(b"AKC1\x05\x00ab").is_err());
        assert!(decode(b"AKC1").unwrap().is_empty());
    }
}
