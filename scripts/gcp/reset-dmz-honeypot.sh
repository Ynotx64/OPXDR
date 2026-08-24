#!/usr/bin/env bash
set -euo pipefail

# Rebuild the disposable OPXDR DMZ honeypot from a known-clean snapshot.
# Run this from Cloud Shell, a trusted admin host, or a tightly scoped scheduler,
# never from inside the honeypot VM itself.

PROJECT="${PROJECT:-detection-lab-506316}"
ZONE="${ZONE:-us-central1-c}"
REGION="${REGION:-us-central1}"
INSTANCE="${INSTANCE:-opxdr-honeypot-dmz}"
DISK="${DISK:-$INSTANCE}"
MACHINE_TYPE="${MACHINE_TYPE:-e2-micro}"
NETWORK="${NETWORK:-opxdr-honeypot-vpc}"
SUBNET="${SUBNET:-opxdr-honeypot-subnet}"
TAGS="${TAGS:-opxdr-honeypot-decoy,opxdr-honeypot-admin}"
COLLECTOR_URL="${COLLECTOR_URL:-http://10.128.0.2:8787}"
AGENT_ID="${AGENT_ID:-opxdr-honeypot-dmz}"
SNAPSHOT="${SNAPSHOT:-}"

if [[ -z "$SNAPSHOT" ]]; then
  SNAPSHOT="$(gcloud compute snapshots list \
    --project "$PROJECT" \
    --filter='name~^opxdr-honeypot-dmz-clean- AND status=READY' \
    --sort-by='~creationTimestamp' \
    --limit=1 \
    --format='value(name)')"
fi

if [[ -z "$SNAPSHOT" ]]; then
  echo "No READY opxdr-honeypot-dmz-clean-* snapshot found. Create a clean baseline snapshot first." >&2
  exit 1
fi

STARTUP_SCRIPT="$(mktemp)"
trap 'rm -f "$STARTUP_SCRIPT"' EXIT

cat >"$STARTUP_SCRIPT" <<EOF
#!/usr/bin/env bash
set -euxo pipefail
OPXDR="$COLLECTOR_URL"
AGENT_ID="$AGENT_ID"
curl -fsS "\$OPXDR/api/opxdr-siem-agent/install.sh?agentId=\$AGENT_ID&name=\$AGENT_ID" -o /tmp/opxdr-siem-agent-install.sh
bash /tmp/opxdr-siem-agent-install.sh
curl -fsS "\$OPXDR/api/honeypot-agent/install.sh?agentId=\$AGENT_ID&services=ssh,http,ftp,smb,smtp" -o /tmp/opxdr-honeypot-agent-install.sh
bash /tmp/opxdr-honeypot-agent-install.sh
iptables -I OUTPUT -d 169.254.169.254/32 -p udp --dport 53 -j ACCEPT || true
iptables -I OUTPUT -d 169.254.169.254/32 -p tcp --dport 53 -j ACCEPT || true
iptables -A OUTPUT -d 169.254.169.254/32 -j REJECT || true
logger -t opxdr-dmz 'OPXDR_DMZ_READY rich_decoys=true disposable_reset=true source_snapshot=$SNAPSHOT'
EOF

echo "Using clean snapshot: $SNAPSHOT"
echo "Marking reset in honeypot logs before rebuild..."
if gcloud compute instances describe "$INSTANCE" --zone "$ZONE" --project "$PROJECT" >/dev/null 2>&1; then
  gcloud compute ssh "$INSTANCE" \
    --zone "$ZONE" \
    --project "$PROJECT" \
    --tunnel-through-iap \
    --command "logger -t opxdr-dmz 'OPXDR_DMZ_RESET_PENDING source_snapshot=$SNAPSHOT'; sudo systemctl restart opxdr-siem-agent.service || true" \
    || true
  sleep 45

  echo "Deleting disposable honeypot instance..."
  gcloud compute instances delete "$INSTANCE" --zone "$ZONE" --project "$PROJECT" --quiet
fi

if gcloud compute disks describe "$DISK" --zone "$ZONE" --project "$PROJECT" >/dev/null 2>&1; then
  echo "Deleting stale honeypot boot disk..."
  gcloud compute disks delete "$DISK" --zone "$ZONE" --project "$PROJECT" --quiet
fi

echo "Creating boot disk from clean snapshot..."
gcloud compute disks create "$DISK" \
  --zone "$ZONE" \
  --project "$PROJECT" \
  --source-snapshot "$SNAPSHOT" \
  --labels opxdr-role=honeypot-dmz,baseline=restored

echo "Recreating honeypot with no external IP and no service account..."
gcloud compute instances create "$INSTANCE" \
  --zone "$ZONE" \
  --project "$PROJECT" \
  --machine-type "$MACHINE_TYPE" \
  --network "$NETWORK" \
  --subnet "$SUBNET" \
  --no-address \
  --no-service-account \
  --tags "$TAGS" \
  --disk "name=$DISK,boot=yes,auto-delete=yes" \
  --metadata-from-file "startup-script=$STARTUP_SCRIPT" \
  --labels opxdr-role=honeypot-dmz,disposable=true

echo "Waiting for startup telemetry..."
sleep 90
gcloud compute instances get-serial-port-output "$INSTANCE" \
  --zone "$ZONE" \
  --project "$PROJECT" \
  --port 1 \
  | egrep 'OPXDR_DMZ_READY|OPXDR_HONEYPOT|decoy_files_ready|source_snapshot' \
  | tail -40 || true

echo "Reset complete. Treat validation from private sources as synthetic/private, not real external attacker traffic."
