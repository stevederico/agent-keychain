# agent-keychain

Secret store for agents. **Runs local, no dependencies. 3.5K LOC.**

An agent gets a secret only after you approve that one request with your login password.

- Linux only (built for Omarchy)
- No account, no cloud, no sync
- Zero-crate Rust: no dependencies, std only (`[dependencies]` is empty)
- About 3.5K lines of Rust, tests included: small enough to read in an afternoon

## How it works

- A small daemon holds the vault as its own system user, so agents running as you cannot read the file or its memory
- An agent asks by name: `agent-keychain get github`
- polkit shows a password prompt: `"agent-keychain <- zsh <- claude" wants the secret "github"`
- Approve and the secret goes to stdout; deny and the client exits 2 with nothing
- Every request is logged: time, secret name, caller, outcome. Never values
- The vault is encrypted with XChaCha20-Poly1305; its key is sealed by `systemd-creds` (TPM2 when present)

## Install

```
./install.sh
```

Builds as you, then asks for sudo to install the daemon, polkit policy and systemd service.

## Update

```
cd ~/Projects/agent-keychain && git pull && ./install.sh
```

Safe to rerun. The vault and its key are never touched.

## Use

```
agent-keychain set github        # store (prompt or stdin), needs approval
agent-keychain get github        # print, needs approval
agent-keychain list              # names only (--json for scripts)
agent-keychain rm github         # delete, needs approval
agent-keychain log               # recent requests (--json for scripts)
agent-keychain skill             # guide for AI agents: point your agent here
agent-keychain doctor            # check the install (service, socket, versions, polkit)
agent-keychain help with         # details for one command
agent-keychain scan              # optional: find keys in plain files (.env, ~/.npmrc, ...)
agent-keychain import ~/.npmrc:5 ~/proj/.env:2=github   # optional: store what scan found, one approval
agent-keychain import --all      # optional: store everything scan finds
agent-keychain with github,npm --for 2h -- claude   # ask once, then no prompts for these

GITHUB_TOKEN=$(agent-keychain get github) gh pr list
```

Exit codes: 0 ok, 1 error, 2 denied, 64 usage. Add `--json` for JSON output and JSON errors (`{"error": ..., "code": ...}`); `get` always prints the raw value.

## Compared to other tools

As of November 2026. Checked against each project's docs and announcements (sources below).

| Tool | Approval | Agent holds the secret | Where secrets live | Status |
| --- | --- | --- | --- | --- |
| **agent-keychain** | Every request, or once per program with `with`; login password; prompt names the secrets and caller | Yes | This machine only | New, Linux only |
| 1Password CLI (`op`, desktop app integration) | Once per terminal session, then a session that refreshes on use | Yes | 1Password cloud, synced | Mature, paid |
| Bitwarden CLI (`bw`) and Bitwarden MCP server | One unlock; the session key then opens the whole vault | Yes | Bitwarden cloud or self-hosted | Mature |
| Bitwarden Agent Access SDK | Per request, human in the loop, end-to-end encrypted | Yes, just in time | Bitwarden vault | Early alpha, not for production |
| Infisical Agent Vault | None per request | No: a proxy adds the credential to outgoing HTTPS requests | Broker's own store or Infisical | Experimental |
| Doppler / Infisical CLI (`run`) | None per request | Yes, as environment variables | Their cloud | Mature, team-focused |
| gnome-keyring / KWallet | None once you are logged in | Yes, any app can read everything | This machine | Mature, Linux default |

**Where agent-keychain is stronger**

- Asks every time, for one named secret, and says who is asking. 1Password and Bitwarden CLI approve a session, so every later request in that terminal, from any agent, goes through
- A click is not enough: approval needs your login password, which an agent cannot type for you
- Agents running as you cannot read the vault, unlike gnome-keyring
- One prompt at a time, and backoff after a denial, so an agent cannot wear you down
- `agent-keychain with` skips prompts only for the program you started, for the secrets and time you approved. Other agents still get asked
- Nothing leaves the machine; no account

**Where it is weaker**

- The agent receives the plaintext secret. Proxy brokers like Infisical Agent Vault never hand it over, so a prompt-injected agent cannot leak it. They only cover HTTPS APIs, though
- No sync, sharing, phone or browser autofill
- Secrets handed to one agent can be read by other agents running as you, through `/proc`. Run agents in their own sandbox (Claude Code and Codex have one) to close that
- Linux and polkit only
- The crypto is a faithful port of libsodium, but the port itself has not been audited
- Young code with no outside users yet

See [SPEC.md](SPEC.md) for the full threat model, including what it does not cover.

### Sources

- 1Password: [app integration security](https://developer.1password.com/docs/cli/app-integration-security), [Touch ID is not enough for agents](https://kovyrin.net/2026/06/04/agent-secret/)
- Bitwarden: [MCP server](https://www.businesswire.com/news/home/20250710815039/en/Bitwarden-Brings-Agentic-AI-to-Secure-Credential-Management), [Agent Access SDK](https://secure.businesswire.com/news/home/20260324779404/en/Bitwarden-Introduces-Open-Standard-to-Secure-Agent-Credential-Access-with-the-Agent-Access-SDK), [community post](https://community.bitwarden.com/t/stop-giving-ai-agents-the-keys-to-everything-introducing-the-agent-access-sdk/95244)
- Infisical: [Agent Vault](https://infisical.com/platform/agent-vault), [credential brokering](https://infisical.com/blog/credential-brokering-for-ai-agents.md), [wiki](https://github.com/Infisical/agent-vault/wiki)
- Doppler and others: [secret tools for AI agents, 2026](https://fast.io/resources/best-secret-management-tools-ai-agents/)

## License

MIT, see [LICENSE](LICENSE). The crypto is ported from libsodium (ISC), notice in [LICENSES/libsodium.txt](LICENSES/libsodium.txt).
