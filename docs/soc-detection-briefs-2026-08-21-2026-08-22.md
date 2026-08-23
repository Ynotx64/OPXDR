# SOC Detection Briefs: August 21-23, 2026

This document captures OPXDR detection engineering notes for the August 21 through August 23 SOC detection briefs. It separates source-driven detection logic from lab validation so replayed or fixture events are never confused with real telemetry.

## Detection Tiers

- Informational: Baseline observation, inventory enrichment, or first evidence that a telemetry source is present.
- Medium: Suspicious new relationship, threshold anomaly, first-time peer, or an unusual but not yet confirmed behavior.
- High: Correlated hostile behavior or a service/process sequence that materially increases confidence.
- Critical: High-confidence unauthorized controller write, confirmed privilege-persistence change, confirmed LSASS dump sequence, or confirmed exploit-to-persistence chain.

## August 21 Brief

### Active Attacks Against Siemens S7 PLCs

Source: CISA Joint Advisory AA26-231A, August 19.

Why it matters: The brief describes active targeting of exposed or poorly segmented Siemens S7 PLCs, including tooling patterns that can interact with S7comm over TCP/102. OPXDR should treat S7 visibility as OT monitoring, not internet-facing bait.

Telemetry needed:

- Zeek, Suricata, firewall, span-port, or OT sensor records for TCP/102.
- Asset inventory labels for approved PLCs and engineering workstations.
- Maintenance-window context.
- Process telemetry for unauthorized `python-snap7` or related tooling on non-engineering hosts.

Detection content:

- `209401`: Baseline Siemens S7/S7comm activity on TCP/102.
- `209402`: First-time S7 peer relationship.
- `209403`: S7 activity from a host not approved as an engineering workstation.
- `209404`: Critical controller write from an unauthorized host.

False-positive notes: New engineering laptops, commissioning windows, NAT changes, and firmware maintenance can create legitimate first-time peer events. Critical controller-write alerts should require both write semantics and unauthorized host context.

### Unauthorized Linux SUID/SGID Changes

Source: Wazuh engineering guide, August 13.

Why it matters: SUID/SGID drift is a durable privilege-persistence signal when compared against an approved baseline.

Telemetry needed:

- Approved privileged-binary baseline with hash, owner, group, mode, package owner, and path.
- FIM events for privileged paths.
- Command-monitoring output for `find` or equivalent privileged-mode scans.
- SCA policy result indicating whether the baseline is present and current.

Detection content:

- `209410`: Baseline telemetry for privileged binaries.
- `209411`: Baseline missing, altered, or tampered.
- `209412`: Unauthorized SUID/SGID mode or new privileged binary.

False-positive notes: Package upgrades can add legitimate SUID binaries. The allowed list should be reviewed after planned package updates rather than suppressing all privileged-mode changes.

### High-Frequency SMB Administrative-Share Writes

Source: Splunk Research, High Frequency Copy of Files in Network Share, updated August 5.

Why it matters: Alerting on every SMB write is noisy. Grouping Windows Event 5145 into short windows and comparing volume to user/host history catches lateral movement and staging with less alert fatigue.

Telemetry needed:

- Windows Security Event 5145 with detailed file-share auditing enabled.
- Share name, relative target path, access mask, account, source host, destination host, and file extension.
- Five-minute aggregation fields such as write count and z-score.

Detection content:

- `209420`: Windows event telemetry baseline.
- `209421`: Administrative-share write observation.
- `209422`: High-frequency administrative-share writes above threshold.

False-positive notes: Software deployment, backup jobs, and admin maintenance can burst writes. Tuning should model user/host baselines and approved administrative tools.

### Captive-Portal Interception and Identity Telemetry

Source: Microsoft CaptiveCrunch/Midnight Blizzard analysis, July 31.

Why it matters: The behavior crosses network, identity, device registration, OAuth, and Microsoft Graph telemetry. The detection should not fire on a normal login alone.

Telemetry needed:

- DNS/HTTP redirection and captive-portal anomalies.
- Entra ID sign-in logs, device-code authentication, new device registration, OAuth grants, and app consent.
- IP/ASN novelty and residential proxy indicators.
- Microsoft Graph mailbox, file, and directory access volume.

Detection content:

- `209430`: Identity telemetry baseline.
- `209431`: Device-code, app-password, OAuth, or new-device registration signal.
- `209432`: Correlated identity abuse plus unusual origin plus Graph/mailbox/file access.

False-positive notes: Travel, new managed devices, and planned app rollouts can resemble part of the chain. High severity requires correlation, not a single successful sign-in.

### Context-Aware Zeek, NetFlow, or IPFIX Detection

Source: Contextualized NetFlow NIDS survey/preprint, February 5.

Why it matters: Per-flow classification misses staged behavior. OPXDR should score host windows and relationship changes over time, then evaluate chronologically to avoid optimistic false results.

Telemetry needed:

- Zeek `conn.log`, NetFlow, or IPFIX records.
- Five-minute host-window features: new peers, destination diversity, failed connection bursts, service diversity, and outbound-byte acceleration.
- Asset and user context.

Detection content:

- `209440`: Flow telemetry baseline.
- `209441`: Contextual flow anomaly.
- `209442`: Correlated staged intrusion behavior.

False-positive notes: Vulnerability scans, backups, patching, and content distribution can trigger volume and diversity features. Keep scanner and backup service labels explicit.

## August 22 Brief

### Actively Exploited Zimbra Command Injection

Sources: CISA KEV addition, August 21; Zimbra security advisory.

Why it matters: The brief calls out command execution risk when vulnerable Zimbra SNMP notification behavior is present. OPXDR should focus on process, FIM, scheduled job, and outbound connection chains.

Telemetry needed:

- Zimbra service inventory and version.
- Process creation for Zimbra-owned services.
- FIM under `/opt/zimbra`.
- Scheduled job creation and outbound connections shortly after mail/SNMP activity.

Detection content:

- `209450`: Application telemetry baseline.
- `209451`: Zimbra SNMP service spawning a shell, interpreter, or download utility.
- `209452`: Critical Zimbra execution chain with unexpected file, scheduled job, or outbound connection.

False-positive notes: Zimbra maintenance scripts can legitimately spawn interpreters. Critical severity should require correlation beyond process name alone.

### Authentication-Flow Abuse by Russian-Linked Clusters

Source: Google Threat Intelligence Group report, August 20.

Why it matters: The behavior extends device-code abuse into app passwords, OAuth grants, linked devices, and token use through legitimate infrastructure.

Telemetry needed:

- Google Workspace and Microsoft Entra audit events.
- App-password creation, OAuth grant, device-code auth, linked-device events, and token usage.
- First-seen redirect domains, first-time application IDs, and unusual IP/ASN.
- Mailbox, drive, Graph, or file access after authorization.

Detection content:

- Covered by `209431` for single identity abuse signals.
- Covered by `209432` when administrative identity changes correlate with unusual origin and data access.

False-positive notes: Helpdesk-driven app enrollment and new mobile-device onboarding can be legitimate. Require identity, network, and post-auth activity correlation before escalation.

### TrueConf Server Vulnerabilities in Active-Exploitation Tracking

Sources: CISA KEV notice, August 20; TrueConf vendor advisory.

Why it matters: TCP/4307 exposure plus service-spawned interpreters or persistence is high-confidence application exploitation behavior.

Telemetry needed:

- Inbound TCP/4307 access logs or flow records.
- TrueConf service process creation.
- File writes outside expected application directories.
- Persistence creation and outbound connections after the inbound session.

Detection content:

- `209460`: TrueConf TCP/4307 access observed.
- `209461`: TrueConf service spawning interpreter or system utility after inbound 4307.
- `209462`: Critical TrueConf exploit-to-host-persistence sequence.

False-positive notes: Support tooling and upgrades can create child processes. Do not escalate to critical without host persistence or equivalent confirmed impact.

### Updated Medusa Credential-Dumping Behavior

Source: CISA/FBI Medusa advisory, updated August 18.

Why it matters: `rundll32` loading `comsvcs.dll` with MiniDump semantics is a common LSASS dump path that can evade simple tool-name detection.

Telemetry needed:

- Sysmon Event 1 process creation.
- Sysmon Event 10 process access to LSASS.
- Sysmon Event 11 dump-file creation.
- EDR or Windows Security process lineage when available.

Detection content:

- `209470`: Sysmon telemetry baseline.
- `209471`: `rundll32` plus `comsvcs.dll` plus MiniDump indicators.
- `209472`: Critical correlated LSASS target and dump-file creation.

False-positive notes: Some forensic and administrative tools can perform memory dumps. Critical severity requires LSASS target context and dump-file creation, not command-line text alone.

## August 23 Brief

### Honeypot Telemetry as Evidence, Not Internet Exposure

Sources: Microsoft, "Inside an AI-enabled device code phishing campaign," April 6, 2026; Microsoft, "OAuth redirection abuse enables phishing and malware delivery," March 2, 2026; Microsoft, "CaptiveCrunch: Midnight Blizzard targets travelers worldwide for malware delivery and credential theft," July 31, 2026.

Direct links:

- https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/
- https://www.microsoft.com/en-us/security/blog/2026/03/02/oauth-redirection-abuse-enables-phishing-malware-delivery/
- https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/

Why it matters: Current identity attacks blend user interaction, OAuth/device-code flows, new device registration, and Microsoft Graph access. OPXDR should correlate honeypot, identity, and flow evidence, but it should not expose lab honeypots directly to the public internet or label controlled probes as live attackers.

Telemetry needed:

- Honeypot listener journal lines tagged `OPXDR_HONEYPOT`.
- OPXDR SIEM agent telemetry with `honeypot_events`, `honeypot_src_ips`, `auth_failures`, and `honeypot_commands`.
- Identity telemetry for device-code auth, OAuth grants, new device registration, unusual ASN, first-seen redirect domains, and Graph/mailbox/file access.
- Flow context for new peers, destination diversity, failed connection bursts, and outbound-byte acceleration.

Detection content:

- `209306`: Medium honeypot traffic observed on cloud agent.
- `209307`: High honeypot source diversity or authentication failure burst.
- `209308`: High honeypot command activity.
- `209431`: Medium identity-flow abuse signal.
- `209432`: High correlated identity abuse plus unusual origin plus Graph/mailbox/file access.

OPXDR-style lab experiment: Keep the cloud honeypot VM private, reachable only from the lab VPC or IAP-controlled administration path. Generate a controlled connection from the collector VM to the honeypot private IP on approved honeypot ports, wait one SIEM-agent heartbeat, and confirm OPXDR creates `209306`. Record the source as synthetic internal lab traffic unless an independently observed external source appears in real telemetry.

False-positive notes: Listener startup messages, internal health checks, vulnerability scanners, and synthetic validation probes are not live attacker evidence. Escalate only when source novelty, auth failures, captured commands, or post-compromise telemetry is present.

### Windows Event 5145 Volume Needs Behavior Context

Sources: Microsoft Security Auditing Event 5145 reference; Microsoft Advanced Audit Policy Configuration guidance.

Direct links:

- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5145
- https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration

Why it matters: Microsoft documents Event 5145 as detailed file-share access auditing and warns that detailed file-share auditing can produce high volume. OPXDR should therefore treat administrative-share writes as medium observations until short-window counts or z-scores exceed a measured baseline.

Telemetry needed:

- Event ID 5145 with source address, account, share name, relative target path, access mask, and outcome.
- Five-minute aggregation features including `write_count`, unique files, unique hosts, and z-score.
- Enrichment for backup, deployment, scanner, EDR, and administrator maintenance accounts.

Detection content:

- `209421`: Medium administrative-share write observation.
- `209422`: High high-frequency administrative-share writes above behavioral threshold.

OPXDR-style lab experiment: In a Windows-only lab, enable detailed file-share auditing on a test server, write a small number of benign files, then replay normalized fixture records with `write_count > 20` for `ADMIN$` or `C$`. Confirm only the aggregated fixture reaches high severity.

False-positive notes: Normal Windows and application access can create many 5145 events. Tune on account, host role, share, process lineage, and maintenance windows instead of suppressing 5145 globally.

### Linux SUID and SGID Changes Remain High-Value Persistence Signals

Source: MITRE ATT&CK T1548.001, Setuid and Setgid.

Direct link:

- https://attack.mitre.org/techniques/T1548/001/

Why it matters: MITRE documents setuid and setgid abuse as a way to execute code in another user or group context. OPXDR should alert on unexpected privileged-bit changes only when they differ from an approved baseline.

Telemetry needed:

- File integrity monitoring for privileged paths.
- Privileged-binary baseline with mode, owner, group, package owner, and hash.
- Package manager update context.
- Audit or command telemetry for `chmod`, `chown`, package installs, and suspicious file creation.

Detection content:

- `209410`: Informational privileged-binary baseline telemetry.
- `209411`: Medium baseline missing, altered, or tampered.
- `209412`: Critical unauthorized SUID or SGID privilege-persistence change.

OPXDR-style lab experiment: In a disposable Linux VM, create a harmless test file, emit normalized baseline telemetry, then set a SUID or SGID mode outside the allowlist. Confirm `209412` fires, remove the file, and verify the alert is clearly labeled as a lab event.

False-positive notes: OS package updates can legitimately add or change privileged binaries. Treat package-context matches as reviewable until hash and package ownership are reconciled.

### Zeek and Flow Windows Should Drive Network Context

Sources: Zeek `conn.log` documentation; Zeek SMB logs documentation.

Direct links:

- https://docs.zeek.org/en/master/reference/logs/conn.html
- https://docs.zeek.org/en/lts/logs/smb.html

Why it matters: Zeek records connection state and byte counters across TCP, UDP, and ICMP-style flows, while SMB logs can tie file-write behavior to lateral movement context. OPXDR should use host-window features instead of isolated single-flow rules.

Telemetry needed:

- Zeek `conn.log` fields for originator, responder, ports, connection state, duration, packets, and bytes.
- Zeek SMB/file events where available.
- Five-minute features for new peers, service and destination diversity, failure bursts, and outbound-byte acceleration.
- Asset labels for scanners, backups, update mirrors, and approved admin hosts.

Detection content:

- `209440`: Informational Zeek, NetFlow, or IPFIX telemetry baseline.
- `209441`: Medium contextual flow anomaly.
- `209442`: High correlated staged-intrusion flow behavior.

OPXDR-style lab experiment: Use an isolated packet fixture or lab-only Zeek sensor to emit one benign host window and one staged host window with new peers, failures, and outbound-byte acceleration. Confirm only the multi-feature staged window maps to high severity.

False-positive notes: Patch mirrors, vulnerability scanners, backup jobs, and content distribution can look like destination diversity or byte acceleration. Require asset labels and historical comparison before escalation.

## Current Real Telemetry Status

At the time these rules were added, the live OPXDR SIEM agent on `soc-admin` was reporting real host telemetry heartbeats only. During the cloud lab setup, `opxdr-honeypot` later reported `opxdr-siem-agent/1.1.1` telemetry with `honeypot_events=58`, `honeypot_src_ips=2`, and `auth_events=40` after controlled private lab validation; OPXDR displayed `TEL-209306-opxdr-honeypot-202608222105` as a medium alert. Those honeypot events include synthetic internal validation traffic and must not be described as live attacker activity. No real Siemens S7, Windows Event 5145, Entra/Graph, Zeek/IPFIX, Zimbra, TrueConf, or Sysmon event source was present in the local repository telemetry. The rules are therefore registry-ready and Wazuh-validated, but they should be tuned against real event volume once those telemetry sources are connected.

## Rollback

The brief-derived rules live in `opxdr_soc_detection_briefs_rules.xml`. To roll them back, remove that file from both OPXDR and Wazuh rule directories, then restart Wazuh manager and refresh OPXDR rules:

```bash
sudo rm -f /var/ossec/etc/rules/opxdr_soc_detection_briefs_rules.xml
rm -f /home/soc-admin/SecurityOperations/custom_rules/opxdr_soc_detection_briefs_rules.xml
sudo systemctl restart wazuh-manager
curl -fsS 'http://127.0.0.1:5173/api/rules?refresh=1' >/dev/null
```
