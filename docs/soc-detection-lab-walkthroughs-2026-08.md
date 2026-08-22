# OPXDR SOC Detection Lab Walkthroughs: August 2026 Briefs

These walkthroughs are for isolated lab validation only. They use sanctioned fixtures, controlled lab services, or replayed logs. Do not describe fixture or replay events as real attacker traffic, and do not expose PLCs, honeypots, vulnerable apps, or lab targets to the public internet.

## 1. Siemens S7 and S7comm Monitoring

Goal: Validate new S7 peer and unauthorized controller-write detections.

Lab boundary:

- Use an isolated network namespace, VM-only segment, or disconnected lab VLAN.
- Use an S7 simulator or captured benign S7comm fixture.
- Do not connect the simulator to the public internet.

Steps:

1. Label approved engineering hosts and PLC simulator assets in OPXDR inventory.
2. Mirror lab traffic to Zeek or Suricata and normalize events with `OPXDR_OT_TELEMETRY`.
3. Generate normal polling from the approved engineering host.
4. Generate a connection from a new lab host to TCP/102.
5. Generate a sanitized controller-write fixture from an unauthorized lab host.
6. Confirm Wazuh maps baseline traffic to `209401`, first-time peer traffic to `209402`, unauthorized engineering traffic to `209403`, and unauthorized write activity to `209404`.

Expected result: New peer is medium, unauthorized S7 host is high, and unauthorized controller write is critical.

Safety stop: If any traffic leaves the lab segment or reaches a physical PLC, stop the test and isolate the lab.

## 2. Linux SUID and SGID Baseline Tampering

Goal: Validate privileged-binary baseline drift and unauthorized SUID/SGID detections.

Lab boundary:

- Use a disposable Ubuntu VM or container-like test host where file mode changes are safe.
- Do not perform this on production hosts.

Steps:

1. Create an approved baseline of SUID/SGID binaries with path, owner, group, mode, package owner, and hash.
2. Configure the OPXDR SIEM agent or Wazuh command monitoring to emit `OPXDR_LINUX_PRIVILEGE_BASELINE`.
3. Confirm normal baseline telemetry maps to `209410`.
4. Temporarily point the baseline path to a missing or altered file and verify `209411`.
5. In the disposable lab only, create a harmless test file and set a privileged mode.
6. Verify `209412` fires for the unauthorized privileged-mode deviation.
7. Restore the baseline and remove the test file.

Expected result: Baseline missing or altered is medium; unauthorized privileged mode is critical.

Safety stop: Do not leave SUID test files behind. Remove test artifacts immediately after validation.

## 3. SMB Administrative-Share Write Burst

Goal: Validate Windows Event 5145 aggregation for administrative-share writes.

Lab boundary:

- Use a Windows lab host and a lab file share.
- Enable detailed file-share auditing only in the lab or through approved change control.

Steps:

1. Enable Event 5145 collection and normalize events with `OPXDR_WINDOWS_EVENT`.
2. Generate ordinary low-volume file writes to a lab share and confirm no high-severity alert.
3. Generate a controlled burst to an administrative share in a lab environment.
4. Aggregate five-minute windows with `write_count` and, when enough history exists, `zscore`.
5. Confirm administrative-share observations map to `209421`.
6. Confirm `write_count > 20` or `zscore >= 3` maps to `209422`.

Expected result: Low-volume admin-share activity is medium; high-frequency behavioral anomaly is high.

Tuning note: Add deployment tools, backup jobs, and scanner identities to enrichment labels before production rollout.

## 4. Captive-Portal and OAuth Abuse Correlation

Goal: Validate identity-flow correlation without alerting on normal login alone.

Lab boundary:

- Use a test tenant and test identities.
- Do not run phishing simulations against real users without explicit authorization.

Steps:

1. In a test tenant, collect Entra or Google Workspace audit logs and normalize them with `OPXDR_IDENTITY_TELEMETRY`.
2. Perform an approved device-code sign-in or test OAuth grant.
3. Confirm single identity-flow signals map to `209431`.
4. Add lab metadata for unusual ASN or first-seen redirect domain.
5. Perform controlled Graph, mailbox, or file-access activity with the test account.
6. Confirm the combined chain maps to `209432`.

Expected result: Single identity-flow signal is medium; identity-flow signal plus unusual origin plus data access is high.

Safety stop: Revoke the test OAuth grant, remove app passwords, and unlink test devices after the lab.

## 5. Context-Aware Zeek NetFlow or IPFIX Features

Goal: Validate host-window network behavior instead of single-flow alerting.

Lab boundary:

- Use OPXDR lab traffic, Zeek connection records, NetFlow, or IPFIX exported from approved lab systems.
- Do not generate scanning traffic against external systems.

Steps:

1. Export connection records into five-minute host windows.
2. Compute `new_peer_count`, `destination_diversity`, `failed_connection_burst`, and `outbound_byte_acceleration`.
3. Normalize feature events with `OPXDR_FLOW_TELEMETRY`.
4. Confirm baseline flow telemetry maps to `209440`.
5. Confirm isolated anomalies map to `209441`.
6. Confirm multi-feature staged behavior maps to `209442`.
7. Evaluate chronologically: train/tune on earlier traffic and test on later traffic.

Expected result: Single contextual anomaly is medium; correlated staged behavior is high.

Tuning note: Maintain allow labels for vulnerability scanners, backup jobs, EDR update mirrors, and package repositories.

## 6. Zimbra Command-Injection Detection

Goal: Validate Zimbra service-to-shell and exploit-chain detections with sanitized fixtures.

Lab boundary:

- Use a Zimbra-like fixture or isolated test service.
- Do not deploy a vulnerable internet-facing Zimbra instance.

Steps:

1. Normalize application process/FIM events with `OPXDR_APP_TELEMETRY`.
2. Replay a benign mail-delivery fixture and confirm it does not fire high or critical rules.
3. Replay a sanitized fixture where `zimbra-snmp` spawns a shell, interpreter, or download utility.
4. Confirm the service-to-child-process fixture maps to `209451`.
5. Add unexpected file, scheduled job, or outbound-connection context.
6. Confirm the correlated sequence maps to `209452`.

Expected result: Service-to-shell is high; execution plus persistence or egress is critical.

Safety stop: Fixture replay must not execute shell commands; it should emit log records only.

## 7. Authentication-Flow Abuse by Cloud Clusters

Goal: Validate app-password, OAuth, device-code, and linked-device abuse patterns.

Lab boundary:

- Use test identities and explicit tenant authorization.
- Do not target real users.

Steps:

1. Create a test app password or OAuth grant for a controlled test application.
2. Emit normalized identity telemetry using `OPXDR_IDENTITY_TELEMETRY`.
3. Confirm the administrative identity change maps to `209431`.
4. Add first-time app ID, unusual IP/ASN, or residential proxy context.
5. Perform controlled mailbox or file access.
6. Confirm the correlated chain maps to `209432`.
7. Revoke the test app password, OAuth grant, and linked device.

Expected result: Administrative identity-flow change is medium; change plus unusual origin plus data access is high.

## 8. TrueConf TCP/4307 Exploitation Sequence

Goal: Validate network-to-process and persistence correlation for TrueConf-like services.

Lab boundary:

- Use a mock service that emits logs. Do not expose a vulnerable TrueConf instance.

Steps:

1. Normalize mock service events with `OPXDR_APP_TELEMETRY`.
2. Emit an inbound TCP/4307 fixture and verify `209460`.
3. Emit a service child-process fixture after inbound 4307 and verify `209461`.
4. Emit host-persistence context after inbound 4307 and verify `209462`.

Expected result: Inbound 4307 is medium; service-spawned interpreter is high; persistence is critical.

Safety stop: The mock service must not execute interpreter payloads. Log-only fixtures are sufficient.

## 9. Medusa comsvcs MiniDump LSASS Behavior

Goal: Validate command-line-only and correlated LSASS dump detections without touching LSASS.

Lab boundary:

- Use sanitized Sysmon fixtures only.
- Do not access, dump, or simulate dumping real LSASS memory.

Steps:

1. Normalize Sysmon fixtures with `OPXDR_SYSMON_TELEMETRY`.
2. Replay a benign `rundll32` fixture and confirm no credential-dumping alert.
3. Replay a sanitized `rundll32` plus `comsvcs.dll` plus `MiniDump` fixture and verify `209471`.
4. Add target-process and dump-file-created fixture fields.
5. Confirm the correlated sequence maps to `209472`.

Expected result: Command-line MiniDump pattern is high; LSASS target plus dump file is critical.

Safety stop: Use fixture events only. Do not invoke MiniDump against any real process.

## Validation Checklist

Run this checklist after any detection update:

```bash
cd /home/soc-admin/OPXDR
sudo /var/ossec/bin/wazuh-analysisd -t
curl -fsS 'http://127.0.0.1:5173/api/rules?refresh=1' >/tmp/opxdr-rules.json
systemctl is-active wazuh-manager
systemctl is-active opxdr-siem-agent
```

Record:

- Rules added or tuned.
- Fixture names and expected rule IDs.
- Real telemetry source availability.
- Real event counts and false-positive observations.
- Rollback file path.
