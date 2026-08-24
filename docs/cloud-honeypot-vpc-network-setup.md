# OPXDR Cloud Honeypot VPC Network Setup

This document defines the first cloud hardening task for OPXDR honeypot telemetry: put internet-facing decoys in a separate cloud VPC/subnet while keeping the collector and any local network unreachable from the honeypot blast radius.

Do not expose PLC simulators, OPXDR, Wazuh, SSH administration, databases, or local-network routes to the public internet. The only public surface should be disposable decoy services that are intentionally instrumented for telemetry.

## Goals

- Place honeypots in a separate cloud VPC and subnet.
- Keep the collector on a private management/telemetry path.
- Prevent routes back to the local network.
- Avoid VPN connectivity from the honeypot VPC into a home LAN.
- Allow the collector to receive logs only.
- Prevent honeypot-initiated SSH to the collector.
- Allow honeypot egress only for OPXDR telemetry/API posts, DNS, package updates when explicitly needed, and tightly scoped monitoring.
- Label events as real external activity only when the source is public internet traffic and not a lab scanner, health check, replay, or synthetic probe.

## Target Topology

```text
Internet
  |
  | allowed only to decoy ports
  v
honeypot-vpc / honeypot-subnet
  |
  | egress allowlist: OPXDR telemetry/API only
  v
collector private API endpoint

No VPN, peering, or route back to local/home network.
No inbound internet to collector.
No public OPXDR, Wazuh, database, or admin SSH.
```

## VPC and Subnet Boundaries

Create a dedicated honeypot VPC for internet-facing decoys. Do not reuse the collector VPC unless firewall policy, routing, and service accounts have already been reviewed and separated.

Recommended segmentation:

- `opxdr-honeypot-vpc`: internet-facing decoy network.
- `opxdr-honeypot-subnet`: subnet for disposable honeypot VMs.
- `opxdr-collector-vpc` or existing private collector subnet: collector and OPXDR API services.
- Private telemetry path from honeypot to collector, limited to the OPXDR telemetry/API port.
- No default route, VPN, VPC peering, or transit path from honeypot to local/home networks.

If a shared VPC is unavoidable, use separate subnets, tags, and firewall rules that produce the same outcome: decoys can be reached from the internet only on safe honeypot ports, and the collector cannot be reached from the public internet.

## Firewall Policy

Use network tags or service accounts to scope firewall rules. Avoid broad rules by IP range alone.

### Inbound To Honeypot

Allow inbound internet only to safe decoy services:

- Fake HTTP: `tcp/8080` or `tcp/80` if intentionally selected.
- Fake SSH: `tcp/2222`, not real admin SSH.
- Fake FTP: `tcp/2121`.
- SMB lure: `tcp/4455`, not real production SMB.
- SMTP lure: `tcp/2525`.

Do not expose:

- Real SSH admin on `tcp/22`.
- OPXDR frontend or backend.
- Wazuh manager, dashboard, or indexer.
- Databases.
- Cloud metadata service.
- PLC simulators or S7/S7comm services.
- Any service with real credentials, real secrets, or privileged cloud access.

### Honeypot To Collector

Allow honeypot egress to the collector only for OPXDR telemetry/API posts.

Recommended rule shape:

- Source: honeypot network tag or honeypot service account.
- Destination: collector private IP or private API endpoint.
- Port: OPXDR telemetry/API port only.
- Protocol: TCP.
- Direction: egress from honeypot, ingress to collector.

Explicitly deny honeypot-to-collector SSH:

- Deny `tcp/22` from honeypot tags to collector tags.
- Deny all other honeypot-to-collector ports unless there is a documented telemetry need.

### Honeypot Egress Guardrails

Default deny egress from the honeypot subnet, then allow only:

- OPXDR telemetry/API posts to the collector.
- DNS to the approved resolver.
- Package repositories only when maintenance windows require updates.
- NTP if required.

Block or tightly control:

- Cloud metadata endpoint access from honeypot workloads.
- Direct outbound SMTP.
- Outbound SSH.
- Broad outbound internet.
- Lateral traffic to private RFC1918 ranges except the collector telemetry endpoint.

## Cloud Identity Guardrails

The honeypot VM should not have meaningful cloud permissions.

Required controls:

- No privileged service account attached to honeypot VMs.
- No broad OAuth scopes.
- No secrets in instance metadata.
- No real API keys, SSH private keys, cloud tokens, or customer data on honeypots.
- Admin access through IAP or a break-glass path, not public SSH.

## Decoy Service Exposure

Expose only decoy services that are safe to observe and reset.

Recommended decoys:

- HTTP login portal with fake admin paths and fake backup filenames.
- SSH-like credential trap on `tcp/2222`.
- FTP banner and login trap on `tcp/2121`.
- SMB lure on `tcp/4455`.
- SMTP relay lure on `tcp/2525`.

Do not run vulnerable real products. Use controlled honeypot listeners that log requests and return safe banners or static responses.

## Disposable Honeypot Design

Make the honeypot interesting enough to attract scanning and probing, but disposable enough that compromise is not consequential.

Use:

- Realistic banners and login prompts.
- Fake admin pages.
- Fake backup paths.
- Fake exposed config names.
- Canary tokens in fake files.
- Daily reset from a clean image or snapshot.
- Immutable base image plus startup configuration.
- Log shipping before reset.

Never use:

- Real secrets.
- Real customer data.
- Production credentials.
- Real PLC simulators.
- Real vulnerable applications connected to other networks.

## Behavior Capture

Capture enough detail to analyze behavior without allowing the honeypot to become a launch point.

Log fields:

- Timestamp.
- Source IP.
- Source port.
- Destination service and port.
- ASN and country when enrichment is available.
- Requested paths.
- User agent.
- Payload preview with length limits.
- Credentials attempted.
- Commands typed inside contained honeypot sessions.
- Session duration and event count.
- Whether the source was public internet, private lab, loopback, known scanner, or synthetic.

Optional sensors:

- Zeek on the honeypot subnet for flow context.
- Suricata for protocol and exploit-signature context.
- NetFlow or IPFIX export for destination diversity and byte acceleration.

## `real_external` Flag

OPXDR should set `real_external=true` only when all of these are true:

- Source IP is public, routable internet space.
- Source is not a known lab scanner, health check, replay source, or synthetic validation host.
- Event was collected from live honeypot telemetry, not a fixture.
- Event timestamp comes from the live sensor path.

Keep `real_external=false` for:

- Collector-to-honeypot validation.
- Loopback self-tests.
- Replay logs.
- Injected fixture events.
- Cloud health checks.
- Known OPXDR lab scanner addresses.

Recommended normalized fields:

```text
event.kind=honeypot
event.source=opxdr-honeypot
event.synthetic=false
event.replayed=false
honeypot.real_external=true|false
honeypot.source_class=public|private_lab|loopback|scanner|synthetic|unknown
honeypot.service=http|ssh|ftp|smb|smtp
honeypot.port=8080|2222|2121|4455|2525
```

## OPXDR Scoring Logic

Use detection tiers consistently.

### Informational

Use informational severity for baseline observations:

- Listener started.
- SIEM agent heartbeat.
- Honeypot inventory update.
- New honeypot service enabled.

Example:

```text
OPXDR_HONEYPOT service=http port=8080 remote=0.0.0.0 preview=listener_started real_external=false
```

### Medium

Use medium severity for suspicious new relationships or threshold anomalies:

- First public source hits a honeypot.
- Port scan plus exploit path probing.
- Public source hits one decoy service with request payload.
- New ASN or country hits a honeypot for the first time.

Example:

```text
honeypot.real_external=true source_class=public service=http request_path=/admin/login
```

### High

Use high severity for correlated hostile behavior:

- Public source hits multiple honeypot services.
- Repeated auth failures.
- Multiple source IPs coordinate against the same honeypot.
- Exploit paths or payload markers appear.
- Dropped payload URL observed.
- Captured command-like input in a contained session.

Example:

```text
honeypot.real_external=true services_touched=3 auth_failures=12 payload_marker=true
```

### Critical

Use critical severity only for high-confidence consequential behavior while still contained:

- Confirmed command execution inside a contained honeypot session.
- Malware retrieval attempt from a captured command or payload URL.
- Persistence attempt observed in the contained session.
- Credential or token theft workflow captured inside the decoy.

Critical honeypot alerts must still state that the activity is isolated and contained.

Example:

```text
honeypot.real_external=true contained_session=true command_executed=true malware_retrieval_attempt=true
```

## Correlation Requirements

Do not call a single noisy event an attacker. Correlate before escalating.

Suggested correlation:

- Public source plus exploit path probing: medium.
- Public source plus multiple services touched: high.
- Public source plus auth burst: high.
- Public source plus payload URL: high.
- Public source plus contained command execution: critical.
- Internal synthetic validation: never above the intended test rule, and always labeled synthetic.

## Reset and Retention

Run honeypots as disposable assets.

Required:

- Snapshot clean image.
- Auto-reset VM daily or after a high-confidence event.
- Ship logs before reset.
- Keep OPXDR alert and telemetry evidence.
- Keep packet captures only when retention policy allows it.
- Rotate fake canary material after reset.

The reset action should run from a trusted admin plane such as Cloud Shell, a
locked-down scheduler runner, or a separate management host. Do not run the
reset controller from inside the honeypot VM, because a compromised decoy could
modify or suppress its own cleanup path.

This repository includes a GCP reset helper:

```bash
scripts/gcp/reset-dmz-honeypot.sh
```

Default behavior:

- Finds the newest READY `opxdr-honeypot-dmz-clean-*` snapshot unless
  `SNAPSHOT=...` is supplied.
- Writes `OPXDR_DMZ_RESET_PENDING` to the honeypot logs and restarts the SIEM
  agent before deletion so the collector has a final pre-reset marker.
- Deletes and recreates only the disposable DMZ honeypot VM and its boot disk.
- Recreates the VM with no external IP, no service account, the DMZ subnet, and
  the honeypot network tags.
- Uses startup configuration to reinstall the OPXDR SIEM agent and honeypot
  decoy agent from the private collector API.
- Prints serial-console evidence for `OPXDR_DMZ_READY`, `OPXDR_HONEYPOT`, and
  `decoy_files_ready`.

Example manual run from Cloud Shell:

```bash
cd ~/src/OPXDR
git pull --ff-only
scripts/gcp/reset-dmz-honeypot.sh
```

Example pinned snapshot run:

```bash
SNAPSHOT=opxdr-honeypot-dmz-clean-20260823191900 scripts/gcp/reset-dmz-honeypot.sh
```

For daily reset automation, schedule the same script from a trusted control
plane after confirming the scheduler identity has only the minimum Compute
permissions required to delete/recreate `opxdr-honeypot-dmz` and read the clean
snapshot. Logs must ship to OPXDR before reset; validation traffic generated by
the scheduler or collector remains `real_external=false`.

## Pre-Deployment Checklist

- Honeypot VPC has no VPN route to home/local networks.
- Honeypot VPC has no route to PLC simulators.
- Collector has no public inbound OPXDR, Wazuh, database, or SSH exposure.
- Honeypot public inbound is limited to decoy ports.
- Honeypot cannot SSH to collector.
- Honeypot egress is default-deny with explicit telemetry allow.
- Honeypot service account has no meaningful permissions.
- Metadata access is blocked or constrained.
- `real_external` flag semantics are implemented and tested.
- Synthetic and replay traffic are visibly labeled.
- Daily reset is configured.
- Logging quotas and rate limits are configured.

## Current Google Cloud Implementation

Project: `detection-lab-506316`

Implemented on August 23, 2026:

- Created dedicated VPC: `opxdr-honeypot-vpc`.
- Created dedicated subnet: `opxdr-honeypot-subnet` in `us-central1`, range `10.77.0.0/24`.
- Created VPC peering:
  - `dmz-to-default`
  - `default-to-dmz`
- Created telemetry-only collector ingress rule on the collector/default network:
  - `opxdr-default-allow-dmz-telemetry-to-collector`: allows `10.77.0.0/24` to `tcp/8787`.
- Created collector SSH deny rule:
  - `opxdr-default-deny-dmz-ssh`: denies `10.77.0.0/24` to `tcp/22`.
- Created DMZ public decoy firewall rule:
  - `opxdr-dmz-allow-public-decoys`: allows `tcp/8080`, `tcp/2222`, `tcp/2121`, `tcp/4455`, and `tcp/2525` only to tagged decoy VMs.
- Created IAP-only admin SSH rule:
  - `opxdr-dmz-allow-iap-admin-ssh`: allows `tcp/22` only from `35.235.240.0/20`.
- Created DMZ egress guardrails:
  - `opxdr-dmz-egress-allow-collector-telemetry`
  - `opxdr-dmz-egress-allow-metadata-dns`
  - `opxdr-dmz-egress-deny-metadata`
  - `opxdr-dmz-egress-deny-rfc1918`
  - `opxdr-dmz-egress-deny-all`
- Created disposable private DMZ VM:
  - `opxdr-honeypot-dmz`
  - Internal IP: `10.77.0.2`
  - Tags: `opxdr-honeypot-decoy`, `opxdr-honeypot-admin`
  - No service account.
  - No external IP.
  - OPXDR SIEM and honeypot agents installed from the private collector API.

Verification observed:

- `opxdr-honeypot-dmz` posted OPXDR SIEM telemetry to the collector.
- Honeypot listeners started for SSH, HTTP, FTP, SMB lure, and SMTP lure.
- Telemetry showed `agent_id=opxdr-honeypot-dmz`, `ip=10.77.0.2`, and `agent_version=opxdr-siem-agent/1.1.1`.
- Honeypot telemetry now labels source class and external status with `public_source_ip_count`, `source_classes`, and `real_external`.
- Rich decoy startup marker was observed:
  - `OPXDR_DMZ_READY rich_decoys=true canary_ids=5 updated=84c5a39`
- Clean baseline snapshot was created:
  - `opxdr-honeypot-dmz-clean-20260823191900`
- Latest observed DMZ telemetry rows showed private-only baseline activity:
  - `dmz_rows`: `52`
  - `honeypot_events`: up to `131`
  - `public_source_ip_count`: `0`
  - `real_external`: `false`

Implemented decoy content:

- Realistic SSH, FTP, SMTP, SMB, and HTTP banners.
- Fake HTTP admin login pages:
  - `/admin`
  - `/admin/login`
- Fake backup directory and files:
  - `/backup/`
  - `/backup/db-backup-2026-08-23.sql`
  - `/backup/vpn-users.csv`
- Fake exposed config paths:
  - `/.env`
  - `/config/.env`
  - `/id_rsa`
  - `/.ssh/id_rsa`
  - `/kubernetes-admin.conf`
- Local fake canary files under `/opt/opxdr-honeypot/decoys`.
- Canary IDs are OPXDR decoys only and do not contain real secrets:
  - `OPXDR-CANARY-DB-001`
  - `OPXDR-CANARY-VPN-002`
  - `OPXDR-CANARY-ENV-003`
  - `OPXDR-CANARY-SSH-004`
  - `OPXDR-CANARY-K8S-005`

The honeypot logs HTTP request paths, canary file access, attempted credentials or payload previews, source class, and `real_external` status. Internal validation and loopback traffic must remain `real_external=false`.

Current blocker:

- Direct public VM exposure is blocked by the project organization policy `constraints/compute.vmExternalIpAccess`.
- Because of that policy, the DMZ VM was created without an external IP. The public decoy firewall rule exists, but no internet traffic can reach the VM until an approved external front door is added.

Next safe exposure options:

- Use an approved external load balancer in front of the DMZ VM if the organization policy allows load balancer forwarding rules.
- Request a scoped exception for `opxdr-honeypot-dmz` external IP access.
- Keep the DMZ VM private and continue internal validation only.

Do not describe current honeypot telemetry as live external attacker behavior
until the source is public routable internet traffic and OPXDR sets
`real_external=true`.

## Rollback

If the honeypot VPC produces unexpected exposure or noisy telemetry:

1. Disable public inbound honeypot firewall rules.
2. Stop honeypot VMs.
3. Preserve logs and OPXDR telemetry for review.
4. Confirm collector and local networks remain unreachable.
5. Revert to the private-only lab topology.
