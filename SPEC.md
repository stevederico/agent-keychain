# agent-keychain spec

2026-11-01

## Goal

agent-keychain is a local secret store that hands a secret to an AI agent only after the user approves that request. It runs on this machine only: no account, no cloud, no sync.

- Agents ask by name: `agent-keychain get github`
- The user approves with their login password in Omarchy's existing polkit prompt
- Every request, approved or denied, is logged

## Threat model

The main threat is a program running as the user that reads secrets without asking. gnome-keyring today lets any such program read everything once the user is logged in.

| Threat | Covered | How |
| --- | --- | --- |
| A program running as the user reads the store | Yes | Files and memory belong to a separate system user |
| An agent fakes the approval click (wtype, ydotool) | Yes | Approval needs the login password, which the agent doesn't have |
| An agent pretends to be another agent | Partly | Caller identity comes from the kernel (PID, exe path), but a script can run under any interpreter |
| An agent leaks a secret after it gets it | No | Out of scope: approval controls who gets a key, not what they do with it |
| Root, or a hacked kernel | No | Root can read anything |
| Stolen disk | Yes | Encrypted at rest |

## How it works

1. `agent-keychaind` runs as system user `agent-keychain` (systemd service, hardened: `ProtectHome`, `NoNewPrivileges`, `MemoryDenyWriteExecute`, no network)
2. It listens on `/run/agent-keychain/sock`, writable only by the user's group
3. A client sends `get github`
4. The daemon reads the caller with `SO_PEERCRED` (uid, pid) and `/proc/<pid>/exe`
5. It asks polkit to authorize action `dev.agent-keychain.read` for that caller; polkit shows the password prompt
6. Approved: it returns the secret over the socket and logs it. Denied: it returns an error and logs it

## Build rules

- Rust, std only, zero crates (`[dependencies]` stays empty, `Cargo.lock` lists only this package)
- No external libraries at runtime. Only glibc (std already links it) and base-system tools (systemd, polkit)
- Crypto: XChaCha20-Poly1305 (IETF), ported line by line from libsodium 1.0.22 reference code (ISC, notice kept in `src/crypto.rs` and `LICENSES/libsodium.txt`)
  - Not invented: same algorithms, same structure, same constant-time tag check
  - Verified by RFC 8439 and draft-irtf-cfrg-xchacha test vectors
  - Differential tests compare against system libsodium on thousands of random inputs (test builds only)
  - Randomness: `getrandom(2)`
  - Why not the kernel's crypto API: Omarchy's kernel sets `crypto.af_alg_restrict = 1`, which blocks unprivileged use
- Syscalls through hand-written `extern "C"` declarations against glibc
- Peer credentials: `getsockopt(SO_PEERCRED)` (std's `peer_cred` is unstable)
- Approval: run polkit's `pkcheck --allow-user-interaction`, no D-Bus crate
- Vault key: run `systemd-creds encrypt/decrypt`
- Every `unsafe` block is small and has a comment saying why it's sound

## Storage and crypto

- One vault file: `/var/lib/agent-keychain/vault`, mode 0600, owned by `agent-keychain`
- Each secret sealed with XChaCha20-Poly1305, fresh random 24-byte nonce per write, secret name as associated data
- Vault key: random 32 bytes, kept sealed by `systemd-creds` (TPM2 when present, else host key), so no extra master password
- Service runs with `MemorySwapMax=0`, so secrets never reach swap; buffers zeroed with volatile writes before free
- No invented crypto: a faithful port of audited code, checked against the original

## CLI

| Command | Does |
| --- | --- |
| `agent-keychain set github` | Store a secret, read from stdin or a hidden prompt. Needs approval |
| `agent-keychain get github` | Print the secret to stdout after approval |
| `agent-keychain list` | Names only, never values |
| `agent-keychain rm github` | Delete a secret. Needs approval |
| `agent-keychain log` | Show recent requests |

Agent use: `GITHUB_TOKEN=$(agent-keychain get github) gh pr list`

## Approval rules

- **Once**: default. One prompt per read
- **For 1 hour**: same caller (exe path) and same secret skip the prompt for 60 minutes
- **Deny**: returns an error; the agent sees "denied"
- Log line: time, secret name, caller exe, pid, result

## Open questions

- Can the polkit prompt show which secret and caller is asking, clearly enough to trust?
- Is "for 1 hour" worth the risk, or always prompt?
- Packaging: a PKGBUILD for omarchy-pkgs, or local only?

## Out of scope

- Sync, phones, browser autofill
- A GUI beyond the polkit prompt
