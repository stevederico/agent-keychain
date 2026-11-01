#!/usr/bin/env bash
# Removes agent-keychain. Keeps the vault and its key unless --purge is given.
set -euo pipefail
[[ $EUID -eq 0 ]] || exec sudo "$0" "$@"

systemctl disable --now agent-keychaind.service 2>/dev/null || true
rm -f /etc/systemd/system/agent-keychaind.service \
  /usr/bin/agent-keychaind /usr/bin/agent-keychain \
  /usr/lib/sysusers.d/agent-keychain.conf \
  /usr/share/polkit-1/actions/dev.agent-keychain.policy
rm -rf /usr/share/doc/agent-keychain /usr/share/licenses/agent-keychain
systemctl daemon-reload

if [[ ${1:-} == --purge ]]; then
  rm -rf /var/lib/agent-keychain /etc/credstore.encrypted/agent-keychain.vault-key
  userdel agent-keychain 2>/dev/null || true
  echo "Removed, including all stored secrets."
else
  echo "Removed. Secrets kept in /var/lib/agent-keychain (use --purge to delete)."
fi
