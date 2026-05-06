#!/usr/bin/env bash
# One-time setup: give soc-admin r/w on the Wazuh rules dir so the
# SOC app can save new custom rules directly. Run with sudo.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo: sudo bash setup-perms.sh"
  exit 1
fi

USER_NAME="${SUDO_USER:-soc-admin}"
WAZUH_RULES_DIR="/var/ossec/etc/rules"
WAZUH_DECODERS_DIR="/var/ossec/etc/decoders"

# Make sure wazuh group exists; if not, fall back to ossec
if getent group wazuh >/dev/null; then
  GRP="wazuh"
elif getent group ossec >/dev/null; then
  GRP="ossec"
else
  GRP="$(stat -c %G "$WAZUH_RULES_DIR")"
fi

echo "[+] Adding $USER_NAME to group: $GRP"
usermod -a -G "$GRP" "$USER_NAME"

echo "[+] chgrp + chmod on $WAZUH_RULES_DIR"
chgrp -R "$GRP" "$WAZUH_RULES_DIR"
chmod -R g+rwX "$WAZUH_RULES_DIR"
find "$WAZUH_RULES_DIR" -type d -exec chmod g+s {} \;

echo "[+] chgrp + chmod on $WAZUH_DECODERS_DIR"
chgrp -R "$GRP" "$WAZUH_DECODERS_DIR"
chmod -R g+rwX "$WAZUH_DECODERS_DIR"
find "$WAZUH_DECODERS_DIR" -type d -exec chmod g+s {} \;

# Allow tail of alerts.json
ALERTS="/var/ossec/logs/alerts/alerts.json"
if [[ -f "$ALERTS" ]]; then
  echo "[+] Granting read on $ALERTS"
  chgrp "$GRP" "$ALERTS" || true
  chmod g+r "$ALERTS" || true
  chmod g+rx /var/ossec/logs /var/ossec/logs/alerts || true
fi

echo
echo "[✓] Done. Log out + back in (or run 'newgrp $GRP') so the new group sticks."
echo "[✓] Then start the app:  cd ~/wazuh-soc-app && npm install && npm run dev"
