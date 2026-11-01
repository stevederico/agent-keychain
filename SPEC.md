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
| An agent pretends to be another agent | Partly | The caller's uid and pid come from the kernel (`SO_PEERCRED`), but its name comes from `/proc/<pid>/comm`, which any process can set |
| An agent wears the user down with repeated prompts | Yes | One prompt at a time; after a denial, no prompts for 30s, doubling per denial in a row up to 10 min |
| An agent draws a fake password prompt to phish the login password | No | Any app can draw a lookalike window. Only type the password into the real polkit prompt |
| An agent reads a secret handed to another process | Partly | A process running as the user can read another's `/proc/<pid>/environ` and open its pipes and files through `/proc/<pid>/fd`, so `TOKEN=$(agent-keychain get x) cmd` exposes the token to any other agent of that user. The client itself is non-dumpable, which closes its own `/proc` entries, but the shell and the command that receive the secret stay readable. Handing the secret over by file descriptor does not help: those are readable the same way. The fix is isolation: start each agent with `agent-keychain run` (see below) |
| An agent puts a fake `agent-keychain` earlier in `PATH` | No | Pairs with the fake prompt above. Call `/usr/bin/agent-keychain` by full path |
| An agent leaks a secret after it gets it | No | Out of scope: approval controls who gets a key, not what they do with it |
| Root, or a hacked kernel | No | Root can read anything |
| Stolen disk | Yes | Encrypted at rest |

## How it works

1. `agent-keychaind` runs as system user `agent-keychain` (systemd service, hardened: `ProtectHome`, `NoNewPrivileges`, `MemoryDenyWriteExecute`, no network)
2. It listens on `/run/agent-keychain/sock`, mode 0666: any local user can connect, but only the owner uid is served
3. A client sends `get github`
4. The daemon reads the caller with `SO_PEERCRED` (uid, pid) and refuses any uid but the owner's
   - It names the caller from `/proc/<pid>/comm` up the parent chain (`agent-keychain <- zsh <- claude`). Processes pick their own names, so this is a hint, not proof
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
| `agent-keychain run claude` | Start an agent that cannot see the user's other processes |

Agent use: `GITHUB_TOKEN=$(agent-keychain get github) gh pr list`

## Approval rules

- **Once**: every `get`, `set` and `rm` prompts (polkit `auth_self`). `list` and `log` never show values and don't prompt
- **Deny**: the client exits 2 and prints nothing
- Log line: time, request, secret name, uid, pid, caller chain, outcome. Never values
- Logged: every request, including `list`, `log`, other users' refused connections and malformed requests
- Outcomes: `allowed`, `stored`, `removed`, `listed`, `shown`, `denied`, `missing`, `error` (approval could not run), `busy`, `throttled`, `refused`, `malformed`
- **One at a time**: while a prompt is open, other requests that need approval fail at once (`busy`) instead of queueing
- **Backoff**: after a denial, requests that need approval fail without a prompt (`throttled`) for 30s (`--deny-backoff`), doubling per denial in a row up to 10 min. Any approval resets it. `list` and `log` are never held back
- Not built yet: "approve for 1 hour"

## Running agents in isolation

Same-user agents can read each other's processes. `agent-keychain run claude` starts the agent in its own PID namespace, so `/proc` shows only its own processes. It runs `/usr/bin/bwrap --dev-bind / / --unshare-pid --proc /proc -- claude` (bubblewrap, by full path so `PATH` cannot swap it).

The agent keeps the user's files and network; it only loses sight of other processes. `agent-keychain get` still works inside: the kernel reports the caller's pid in the daemon's namespace.

## Open questions

- Can the polkit prompt show which secret and caller is asking, clearly enough to trust? Omarchy's shell polkit agent shows the action message, which carries both, if polkit accepts the details (see the owner annotation below)
- Proxy mode: hand the agent a placeholder and swap in the real secret on its outgoing HTTPS requests, so the agent never holds it. Needs TLS (breaks the zero-crate rule or means a port) or plugging into an existing proxy (cloak, OneCLI, Infisical Agent Vault)
- Add "approve for 1 hour", or keep always-prompt?
- Confirm on a real install: polkit honors the `org.freedesktop.policykit.owner` annotation for the daemon user
- Packaging: a PKGBUILD for omarchy-pkgs, or local only?

## Out of scope

- Sync, phones, browser autofill
- A GUI beyond the polkit prompt
