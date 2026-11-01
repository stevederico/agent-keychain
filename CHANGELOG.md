- Test real polkit install
- Consider 1-hour approval
- Add proxy mode (agent never sees secret; plug into cloak/OneCLI or own TLS)

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
