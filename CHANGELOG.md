- Add proxy mode (agent never sees secret; plug into cloak/OneCLI or own TLS)
- Add agent-browser login plugin (credential.read, agent never sees password)
- Add Mac support (Authorization Services, launchd, Keychain, libproc, LOCAL_PEERCRED/audit token, getentropy, PT_DENY_ATTACH, macOS struct layouts in sys.rs)

0.24.0

  Highlight no dependencies

0.23.0

  Add MIT license

0.22.0

  Add doctor command
  Add per-command help
  Add JSON errors
  Add daemon version request
  Point agents to skill

0.21.0

  Add --version

0.20.0

  Add batch import
  Add import --all
  Refuse import overwrites

0.19.0

  Add scan command
  Add import command

0.18.0

  Sync crate version
  Expand Mac to-do

0.17.0

  Clear done to-dos

0.16.0

  Plan Mac support

0.15.0

  Plan login plugin

0.14.0

  Add skill command
  Add JSON output

0.13.0

  Document updating

0.12.0

  Signal systemd readiness
  Record install findings

0.11.1

  Fix with across users

0.11.0

  Add with command
  Remove run command

0.10.0

  Plan proxy mode

0.9.0

  Add README
  Add tool comparison

0.8.0

  Add run command

0.7.0

  Hide client from /proc
  Document agent isolation

0.6.0

  Add prompt lock
  Add denial backoff
  Expand threat model
  Drop unused code

0.5.0

  Log every request
  Log failed replies
  Separate approval errors
  Fix rm race
  Tail log cheaply
  Restore echo on Ctrl-C
  Fix install re-exec
  Block stale installs
  Gate release tests
  Correct spec

0.4.0

  Add daemon
  Add CLI
  Add install scripts
  Add end-to-end tests

0.3.0

  Port libsodium crypto
  Add test vectors
  Add libsodium cross-checks
  Drop kernel crypto

0.2.0

  Expand gitignore

0.1.0

  Add spec
  Add kernel crypto
  Add vault format
  Add wire protocol
  Add peer lookup
