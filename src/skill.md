# agent-keychain: guide for AI agents

The user keeps secrets (API tokens, passwords) in agent-keychain. You get one only after the user approves your request with their password.

## Get a secret

Use it inline, in the one command that needs it:

```
GITHUB_TOKEN=$(agent-keychain get github) gh pr list
```

- `agent-keychain list` shows the names. It never prompts. `list --json` gives a JSON array
- `agent-keychain log --json` shows recent requests and their outcomes as JSON
- Each `get` shows the user a password prompt naming the secret and your process

## Rules

- Never print, echo, log or write a secret to a file, and never paste one into your reply
- Never store a secret in a variable that outlives the command
- Ask for the narrowest secret the task needs, and only when you need it
- The user sees every request in `agent-keychain log`

## Exit codes

| Code | Meaning | What to do |
| --- | --- | --- |
| 0 | Approved | Continue |
| 2 | Denied | Stop. Ask the user why; do not retry |
| 1 | Error | Read the message. `busy`: another prompt is open, wait for it. `try again in Ns`: a recent denial, wait or ask the user. `no secret named x`: ask the user to run `agent-keychain set x` |
| 64 | Usage | Fix the command |

Never retry a denied or throttled request in a loop.

Add `--json` to get errors as `{"error": "...", "code": 2}` (not for `get`, which always prints the raw value). If nothing works, run `agent-keychain doctor` and show the user its output.

## Many requests

If a task needs the same secret many times, ask the user to start you with:

```
agent-keychain with github --for 2h -- <your command>
```

They approve once; you and your child processes then get `github` without prompts until it expires. You cannot set this up yourself without the user approving it.

## Rules the user set

The user may allow or deny agents by process name (`agent-keychain rules` lists them).

- An allow rule for you: `get` returns with no prompt
- A deny rule: `get` exits 2 at once, with no prompt. Treat it as a denial: stop, do not retry
- Never run `allow`, `deny` or `unallow`. They need the user's password, and they are refused from inside an agent anyway
- Never rename your process or run under another agent's name to match a rule

## Do not

- Do not run `set`, `rm` or `import` unless the user asked you to change secrets
- `agent-keychain scan` is the user's tool for finding keys in plain files; run it only when asked
- Do not try to read secrets from other processes or from the vault files
