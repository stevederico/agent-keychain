# agent-keychain spec

2026-11-02

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
| An agent reads a secret handed to another process | Partly | A process running as the user can read another's `/proc/<pid>/environ` and open its pipes and files through `/proc/<pid>/fd`, so `TOKEN=$(agent-keychain get x) cmd` exposes the token to any other agent of that user. The client itself is non-dumpable, which closes its own `/proc` entries, but the shell and the command that receive the secret stay readable. Handing the secret over by file descriptor does not help: those are readable the same way. The fix is isolation: run agents in their own sandbox (Claude Code and Codex both offer one, using bubblewrap on Linux) |
| A program names itself after an allowed agent (`claude`) to get a secret with no prompt | No, by design | Agent rules match `/proc/<pid>/comm`, which each process sets for itself. `allow` trusts that name; only allow secrets you would give any program running as the user. `*` is refused for `allow`, so a spoofed name never reaches the whole vault |
| A program renames itself to dodge a `deny` rule | Yes | It falls back to the normal prompt. `deny` only ever removes prompts by refusing; it never grants anything |
| An agent changes the rules to allow itself | Yes | Rule changes need the login password (polkit `dev.agent-keychain.rule`), and are refused with no prompt when the asking chain contains the agent named in the rule or any agent that has a rule. The rules file belongs to the daemon user |
| A granted program uses a secret without the user seeing a prompt | By design | Only after `with` was approved, only for the secrets and time named in that prompt, at most 12h |
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
- Agent rules: `/var/lib/agent-keychain/rules`, mode 0600, owned by `agent-keychain`, plain text (names only, no secrets)
- Each secret sealed with XChaCha20-Poly1305, fresh random 24-byte nonce per write, secret name as associated data
- Vault key: random 32 bytes, kept sealed by `systemd-creds` (TPM2 when present, else host key), so no extra master password
- Service runs with `MemorySwapMax=0`, so secrets never reach swap; buffers zeroed with volatile writes before free
- No invented crypto: a faithful port of audited code, checked against the original

## CLI

| Command | Does |
| --- | --- |
| `agent-keychain set github` | Store a secret, read from stdin or a hidden prompt. Needs approval |
| `agent-keychain get github` | Print the secret to stdout after approval |
| `agent-keychain list` | Names only, never values. `--json` for a JSON array |
| `agent-keychain rm github` | Delete a secret. Needs approval |
| `agent-keychain log` | Show recent requests. `--json` for an array of objects |
| `agent-keychain skill` | Print the guide for AI agents, built into the binary |
| `agent-keychain doctor` | Check the install: first `agent-keychain` in `PATH` (an earlier one could fake the flow), service, socket, daemon version against the client's (`VERSION` request), polkit policy, `pkcheck` |
| `agent-keychain help <cmd>`, `<cmd> --help` | Details for one command |
| `--json` | JSON output for `list`, `log`, `scan`, `doctor`, `set`, `rm`, `import`, `--version`, and errors as `{"error", "code"}`. Not for `get`, which always prints the raw value for inline use |
| `agent-keychain scan [dir]` | Optional. Find secrets in plain files: `.env` files, shell config, `~/.npmrc`, `~/.aws/credentials`, `~/.netrc`, `~/.git-credentials`, `~/.config/gh/hosts.yml`, `~/.docker/config.json`. Read only, runs as the user, sends nothing anywhere. Shows file, line, variable and a preview (known prefix and last 4), never the value. Skips hidden and dependency folders |
| `agent-keychain import <file>:<line>[=name]...` | Optional. Store secrets `scan` found, all under one approval (`SETMANY`, one vault write: all or none). `--all` takes everything a home scan finds, each value once, renaming around taken names (`github-2`). Never overwrites a stored name and never edits the file: the plain copy stays until the user removes it |
| `agent-keychain with github --for 2h -- claude` | Run a program that may `get` these secrets without a prompt. Asks once |
| `agent-keychain allow claude github` | Let agent `claude` `get` `github` with no prompt. Needs approval |
| `agent-keychain deny codex '*'` | Refuse agent `codex` a secret, or all with `*`, with no prompt (exit 2). Needs approval |
| `agent-keychain unallow claude github` | Remove the allow or deny rule for that agent and secret. Needs approval |
| `agent-keychain rules` | List rules. Never prompts. `--json` for an array of `{effect, agent, secret}` |

Agent use: `GITHUB_TOKEN=$(agent-keychain get github) gh pr list`

## Approval rules

- **Once**: every `get`, `set` and `rm` prompts (polkit `auth_self`), unless an agent rule or a `with` grant decides a `get`. `list` and `log` never show values and don't prompt
- **Deny**: the client exits 2 and prints nothing
- Log line: time, request, secret name, uid, pid, caller chain, outcome. Never values
- Logged: every request, including `list`, `log`, other users' refused connections and malformed requests
- Outcomes: `allowed`, `allowed-by-grant`, `allowed-by-rule`, `approved` (a `with` grant), `stored`, `removed`, `listed`, `shown`, `denied`, `denied-by-rule`, `changed` (a rule), `unchanged` (that rule already existed), `missing`, `error` (approval could not run), `busy`, `throttled`, `refused`, `malformed`
- Rule requests log as `RULE-ALLOW`, `RULE-DENY`, `RULE-RM` and `RULES`, with `agent:secret` in the name column
- **One at a time**: while a prompt is open, other requests that need approval fail at once (`busy`) instead of queueing
- **Backoff**: after a denial, requests that need approval fail without a prompt (`throttled`) for 30s (`--deny-backoff`), doubling per denial in a row up to 10 min. Any approval resets it. `list` and `log` are never held back
- **With**: `agent-keychain with github,npm --for 2h -- claude` asks once (`"..." wants "github,npm" without asking, for 2h`), then execs the program
  - The program and everything it starts may `get` those secrets without a prompt until the time is up (default 1h, at most 12h) or the program exits
  - The grant is tied to the program's pid and start time. A request matches if that process is the asker or one of its ancestors, read from the kernel's parent links in `/proc/<pid>/stat`, which a process cannot fake
  - The ancestry is read twice and compared, and the asker is confirmed alive through its pidfd (`SO_PEERPIDFD`), so a pid freed and reused mid-request cannot borrow a grant
  - Only `get`. `set` and `rm` always prompt. Other secrets and other programs still prompt
  - Grants live in the daemon's memory only; a restart drops them
- **Agent rules**: `allow <agent> <secret>`, `deny <agent> <secret|*>`
  - Order for a `get`: a matching deny rule refuses (`denied-by-rule`, exit 2), then a matching allow rule returns the secret (`allowed-by-rule`), then a `with` grant, then the prompt
  - A rule deny prompts nobody, so it does not start or extend the backoff. An allow rule is not held back by the backoff, like a grant
  - Identity: the asking process's ancestry from `/proc/<pid>/stat`, read twice and compared with the asker confirmed alive through its pidfd (as for `with`). Each process's `/proc/<pid>/comm` is read between the two reads, so every name belongs to that pid and start time. The `agent-keychain` client itself (chain[0], when so named) is skipped
  - Deny wins: if any process in the chain has a deny rule for the secret (or `*`), refuse
  - Otherwise the agent is the nearest process whose name has any rule. Its own allow rule for the secret skips the prompt; without one, prompt. So `codex` under `claude` is judged as `codex` and does not inherit `claude`'s allows
  - If the chain cannot be read reliably, the rules are skipped and the request prompts
  - Names: exact match, 1 to 15 of `A-Z a-z 0-9 . _ -` (the kernel keeps 15 bytes of a name), not `agent-keychain`. Secrets: a secret name, or `*` for deny only. One rule per agent and secret; a new one replaces the old
  - Changes (`allow`, `deny`, `unallow`) need approval through polkit action `dev.agent-keychain.rule`; the prompt names the change: `"agent-keychain <- zsh" wants to allow "claude" to get "github" without asking`. A separate action, not `write`, so the prompt can say exactly what changes. Installs before 0.28.0 need `./install.sh` rerun to get it (`doctor` reports the old policy)
  - A change is refused with no prompt (`refused`) when the asking chain contains the agent named in the rule, or any process that has a rule, so an agent cannot ask to allow itself. Change rules from a plain terminal. Setting a rule on a shell's name (`zsh`) means rule changes must then come from a different shell
  - Stored in `/var/lib/agent-keychain/rules`, mode 0600, owned by the daemon user, written to a temp file, fsynced and renamed like the vault. Plain lines: `allow claude github`, `deny codex *`, `#` comments. At most 256 rules. A malformed file stops the daemon at start with the line number, rather than serving without rules

## Confirmed on a real install (2026-11-01, Omarchy)

- The polkit prompt shows the secret and caller: `"agent-keychain ← bash ← ghostty ← Hyprland" wants to change the secret "github"`
- polkit honors the `org.freedesktop.policykit.owner` annotation, so the daemon user may pass those details
- `with` works across users: one prompt, then `allowed-by-grant` for the program and its children

## Open questions

- Proxy mode: hand the agent a placeholder and swap in the real secret on its outgoing HTTPS requests, so the agent never holds it. Needs TLS (breaks the zero-crate rule or means a port) or plugging into an existing proxy (cloak, OneCLI, Infisical Agent Vault)
- Packaging: a PKGBUILD for omarchy-pkgs, or local only?

## Out of scope

- Sync, phones, browser autofill
- A GUI beyond the polkit prompt
