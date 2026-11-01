#!/usr/bin/env bash
# Builds and installs agent-keychain system-wide for the user who runs it.
# Usage: ./install.sh   (builds as you, then asks for sudo)
set -euo pipefail
cd "$(dirname "$0")"

if [[ $EUID -ne 0 ]]; then
  cargo build --release --locked
  exec sudo "$0"
fi

owner_uid=${SUDO_UID:?run ./install.sh as your user, not as root}

install -Dm755 target/release/agent-keychaind /usr/bin/agent-keychaind
install -Dm755 target/release/agent-keychain /usr/bin/agent-keychain
install -Dm644 dist/agent-keychain.sysusers /usr/lib/sysusers.d/agent-keychain.conf
install -Dm644 dist/dev.agent-keychain.policy /usr/share/polkit-1/actions/dev.agent-keychain.policy
install -Dm644 SPEC.md /usr/share/doc/agent-keychain/SPEC.md
install -Dm644 LICENSES/libsodium.txt /usr/share/licenses/agent-keychain/libsodium.txt
sed "s/@OWNER_UID@/$owner_uid/" dist/agent-keychaind.service >/etc/systemd/system/agent-keychaind.service
chmod 644 /etc/systemd/system/agent-keychaind.service

systemd-sysusers agent-keychain.conf

# The vault key: random, sealed by systemd-creds (TPM2 when present, else the host key).
# Never overwritten: losing it makes the vault unreadable.
cred=/etc/credstore.encrypted/agent-keychain.vault-key
if [[ ! -e $cred ]]; then
  install -dm700 /etc/credstore.encrypted
  /usr/bin/agent-keychaind --gen-key | systemd-creds encrypt --name=vault-key - "$cred"
  chmod 600 "$cred"
fi

systemctl daemon-reload
systemctl enable agent-keychaind.service
systemctl restart agent-keychaind.service
systemctl --no-pager --lines=3 status agent-keychaind.service || true
echo
echo "Installed. Try: agent-keychain set github"
