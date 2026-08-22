import { useContext, useEffect, useRef, useState } from "react";
import { OpxdrContext } from "../App";
import { BookOpen, ChevronDown, ChevronRight, Plus, Search, X, Copy, Send, PlayCircle, FileText } from "../lib/icons";
import { api, callAgent, SEV_HEX } from "../lib/api";

// ─── STATIC REGISTRY ────────────────────────────────────────────────────────
const STATIC_REG = {
  honeypot: { label: "Honeypot Cluster", color: "#f97316", icon: "🍯", rules: [
    { id: "HP-010", file: "010-cowrie_rules.xml", name: "Cowrie SSH/Telnet Honeypot", tactic: "Initial Access", mitre: "T1110", severity: "HIGH" },
    { id: "HP-030", file: "030-heralding_rules.xml", name: "Heralding Credential Honeypot", tactic: "Credential Access", mitre: "T1078", severity: "CRITICAL" },
    { id: "HP-050", file: "050-mailoney_rules.xml", name: "Mailoney SMTP Trap", tactic: "Phishing", mitre: "T1566", severity: "HIGH" },
    { id: "HP-090", file: "090-ciscoasa_rules.xml", name: "CiscoASA Emulator", tactic: "Initial Access", mitre: "T1190", severity: "CRITICAL" },
    { id: "HP-110", file: "110-conpot_rules.xml", name: "Conpot ICS/SCADA Honeypot", tactic: "Initial Access", mitre: "T1190", severity: "CRITICAL" },
    { id: "HP-180", file: "180-correlation_rules.xml", name: "Cross-Honeypot Correlation", tactic: "Multiple Stages", mitre: "CORR", severity: "CRITICAL" },
  ]},
  aptpack: { label: "APTPACK Threat Packs", color: "#ef4444", icon: "☠️", rules: [
    { id: "AP-IA", file: "APTPACK-IA/ia-wazuh.xml", name: "Initial Access Detection", tactic: "Initial Access", mitre: "T1566,T1190,T1078", severity: "CRITICAL" },
    { id: "AP-EXEC", file: "APTPACK-EXEC/exec-wazuh.xml", name: "Execution — Encoded Cmd & Eval", tactic: "Execution", mitre: "T1059,T1027", severity: "HIGH" },
    { id: "AP-PE", file: "APTPACK-PE/pe-wazuh.xml", name: "Privilege Escalation & Persist", tactic: "Privilege Escalation", mitre: "T1068,T1547", severity: "CRITICAL" },
    { id: "AP-DISC", file: "APTPACK-DISC/disc-wazuh.xml", name: "Discovery — Net Scan & Low/Slow", tactic: "Discovery", mitre: "T1046,T1018", severity: "MEDIUM" },
    { id: "AP-CA", file: "APTPACK-CA/ca-wazuh.xml", name: "C2 Beacon & Jitter", tactic: "Command & Control", mitre: "T1071,T1573", severity: "CRITICAL" },
    { id: "AP-STG", file: "APTPACK-STAGE/stage-wazuh.xml", name: "Staging — Upload & Chunking", tactic: "Exfiltration", mitre: "T1030,T1041", severity: "HIGH" },
  ]},
  apt31: { label: "APT31 (Zirconium)", color: "#a855f7", icon: "🐼", rules: [
    { id: "A31-03", file: "apt31_password_spray_privileged_accounts.yml", name: "Password Spray — Privileged Accts", tactic: "Credential Access", mitre: "T1110.003", severity: "CRITICAL" },
    { id: "A31-05", file: "apt31_targeted_phishing_to_privileged_signin.yml", name: "Phishing → Privileged Sign-in", tactic: "Initial Access", mitre: "T1566,T1078", severity: "CRITICAL" },
  ]},
  ifrag: { label: "iFrag-DHV (RDP)", color: "#06b6d4", icon: "🖥️", rules: [
    { id: "RDP-03", file: "windows_rdp_bruteforce.yml", name: "Windows RDP Bruteforce", tactic: "Credential Access", mitre: "T1110.001", severity: "CRITICAL" },
    { id: "RDP-04", file: "windows_rdp_success_after_failures.yml", name: "RDP Success After Failures", tactic: "Initial Access", mitre: "T1078", severity: "CRITICAL" },
  ]},
  edge: { label: "Edge Appliance / VPN", color: "#38bdf8", icon: "🔀", rules: [
    { id: "EDG-03", file: "edge-logging-disabled-or-redirected.yml", name: "Logging Disabled/Redirected", tactic: "Defense Evasion", mitre: "T1562.002", severity: "CRITICAL" },
    { id: "EDG-04", file: "edge-unexpected-egress.yml", name: "Unexpected Egress Traffic", tactic: "Exfiltration", mitre: "T1048", severity: "HIGH" },
  ]},
  malware: { label: "Malware (YARA)", color: "#fb7185", icon: "🦠", rules: [
    { id: "MAL-01", file: "detect_Redline_Stealer.yar", name: "Redline Stealer", tactic: "Credential Access", mitre: "T1555,T1539", severity: "CRITICAL" },
  ]},
};

const TACTIC_LIST = ["Initial Access", "Execution", "Privilege Escalation", "Lateral Movement", "Credential Access", "Discovery", "Command & Control", "Exfiltration", "Collection", "Persistence", "Defense Evasion", "Impact"];
const MITRE_OPTS = ["T1059", "T1078", "T1110", "T1110.001", "T1110.003", "T1021", "T1046", "T1027", "T1190", "T1203", "T1566", "T1071", "T1573", "T1041", "T1048", "T1562", "T1547", "T1068", "T1555"];

// Known save paths — defaults listed first (most common top)
const RULE_SAVE_PATHS = [
  { label: "Custom Rules (App Default)",        path: "/home/soc-admin/SecurityOperations/custom_rules" },
  { label: "Wazuh Native Rules Dir",            path: "/var/ossec/etc/rules" },
  { label: "GitHub Staging Rules",              path: "/home/soc-admin/SecurityOperations/github-staging/rules" },
  { label: "APTPACK Staging",                   path: "/home/soc-admin/SecurityOperations/github-staging/rules/APTPACK" },
  { label: "Malware Detection Staging",         path: "/home/soc-admin/SecurityOperations/github-staging/rules/MalwareDetection" },
  { label: "Custom Playbooks Dir",              path: "/home/soc-admin/SecurityOperations/custom_playbooks" },
  { label: "Custom (type below)",               path: "__custom__" },
];

function sevFromLevel(l) {
  const n = parseInt(l);
  if (n >= 15) return "CRITICAL";
  if (n >= 12) return "HIGH";
  if (n >= 7)  return "MEDIUM";
  return "LOW";
}

function buildXML(f) {
  const mitreIds = f.mitreTechniques.filter(Boolean).map(t => `      <id>${t}</id>`).join("\n");
  const fields   = f.fieldConditions.filter(c => c.name && c.value).map(c =>
    `    <field name="${c.name}"${c.negate ? ' negate="yes"' : ""}>${c.value}</field>`
  ).join("\n");
  return `<!-- Generated by OPXDR Rule Writer -->
<group name="${f.groupName},">
  <rule id="${f.ruleId}" level="${f.level}">
    ${f.decoderAs ? `<decoded_as>${f.decoderAs}</decoded_as>` : ""}
${fields ? fields + "\n" : ""}    <description>${f.description}</description>
${mitreIds ? `    <mitre>\n${mitreIds}\n    </mitre>` : ""}
    <group>${f.groupName},${f.tactic.toLowerCase().replace(/ /g, "_")},</group>
  </rule>
</group>`;
}

function buildSigma(f) {
  const techniques = f.mitreTechniques.filter(Boolean);
  const conditions = f.fieldConditions.filter(c => c.name && c.value);
  const detection = conditions.length
    ? conditions.map((c, i) => `    field${i + 1}:\n        ${c.name}: '${c.value}'`).join("\n")
    : `    keywords:\n        - '${f.description}'`;
  return `title: ${f.description || "Untitled Detection"}
id: ${f.ruleId}
status: experimental
description: ${f.description || "Custom detection rule authored by OPXDR"}
author: OPXDR Rule Writer
date: ${new Date().toISOString().slice(0, 10)}
tags:
${techniques.map(t => `    - attack.${t.toLowerCase().replace(".", "_")}`).join("\n") || "    - attack.discovery"}
logsource:
    category: ${f.decoderAs || "process_creation"}
    product: linux
detection:
${detection}
    condition: ${conditions.length > 1 ? conditions.map((_, i) => `field${i + 1}`).join(" and ") : "field1"}
level: ${f.severity.toLowerCase()}
falsepositives:
    - Legitimate administrative activity
`;
}

function buildYARA(f) {
  const conditions = f.fieldConditions.filter(c => c.name && c.value);
  const strings = conditions.map((c, i) =>
    `        $s${i + 1} = /${c.value}/ ascii wide`
  ).join("\n");
  const cond = conditions.length
    ? conditions.map((_, i) => `$s${i + 1}`).join(" and ")
    : "true";
  return `/* OPXDR YARA Rule — ${f.description || "Custom Detection"} */
/* MITRE: ${f.mitreTechniques.filter(Boolean).join(", ") || "N/A"} */

rule ${(f.groupName || "custom_detection").replace(/[^a-zA-Z0-9_]/g, "_")}_${f.ruleId} {
    meta:
        description = "${f.description || "Custom YARA detection"}"
        severity    = "${f.severity}"
        tactic      = "${f.tactic}"
        author      = "OPXDR Rule Writer"
        date        = "${new Date().toISOString().slice(0, 10)}"
${f.mitreTechniques.filter(Boolean).map(t => `        mitre       = "${t}"`).join("\n")}

    strings:
${strings || '        $s1 = "suspicious_pattern" ascii wide'}

    condition:
        ${cond}
}
`;
}

function buildIRPlaybook(f) {
  const techniques = f.mitreTechniques.filter(Boolean);
  return `# Incident Response Playbook
# Auto-generated by OPXDR Rule Writer
# Rule: ${f.ruleId} — ${f.description || "Custom Detection"}

playbook:
  id: IR-${f.ruleId}
  title: "${f.description || "Custom Detection"} — Response"
  severity: ${f.severity}
  tactic: "${f.tactic}"
  mitre: [${techniques.map(t => `"${t}"`).join(", ")}]
  created: ${new Date().toISOString().slice(0, 10)}

triage:
  - Confirm alert is not a false positive from legitimate activity
  - Identify source host, user, and process associated with the event
  - Check asset inventory for host classification (critical/standard)
  - Pull last 24h of logs from affected endpoint

containment:
  - Isolate affected endpoint from network if lateral movement suspected
  - Reset credentials for any involved accounts
  - Block source IP at perimeter firewall if external origin
  - Preserve volatile memory (if host is live and accessible)

eradication:
  - Remove malicious artifacts, scheduled tasks, or persistence mechanisms
  - Revoke and rotate any exposed credentials or tokens
  - Patch or mitigate the exploited vulnerability

recovery:
  - Restore endpoint from known-good backup if integrity compromised
  - Re-enable network access after containment verified
  - Monitor endpoint for 72h post-recovery for re-infection

post_incident:
  - Update detection rule with any new indicators
  - Add new IOCs to threat intel feeds
  - Document timeline and lessons learned
  - Update asset risk score if appropriate

notes: ""
`;
}

// ─── AGENT TYPE DEFINITIONS ──────────────────────────────────────────────────
// ─── ENDPOINT AGENT DEFINITION ───────────────────────────────────────────────
const ENDPOINT_AGENT = {
  label: "Endpoint Agent",
  color: "#f97316",
  icon:  "🖥️",
  desc:  "Process creation · FIM · Registry · ETW/eBPF · Memory scanning · Local detections",
  why:   "Memory safety · Static binaries · High performance · Minimal runtime deps",
  modules: [
    { id: "process_monitoring",  label: "Process Creation Monitoring", on: true  },
    { id: "file_integrity",      label: "File Integrity Monitoring",   on: true  },
    { id: "registry_monitoring", label: "Registry Monitoring",         on: false },
    { id: "etw_ebpf",            label: "ETW / eBPF Collection",       on: true  },
    { id: "memory_scanning",     label: "Memory Scanning",             on: false },
    { id: "local_detections",    label: "Local Detections",            on: true  },
    { id: "secure_comms",        label: "Secure Communications",       on: true  },
  ],
  fields: [
    { id: "gatewayUrl", label: "Gateway URL",     placeholder: "https://gateway.opxdr:8443" },
    { id: "heartbeat",  label: "Heartbeat (sec)", placeholder: "30" },
    { id: "targetOs",   label: "Target OS",       placeholder: "linux,windows" },
  ],
};

function buildAgentConfig(name, desc, mods, extras) {
  const e    = Object.fromEntries(mods.map(m => [m.id, m.on]));
  const id   = `endpoint-${Date.now().toString(36)}`;
  const date = new Date().toISOString().slice(0, 10);
  return `# OPXDR Endpoint Agent Configuration
# Generated by OPXDR Agent Writer — ${date}

[agent]
name        = "${name || "opxdr-endpoint"}"
id          = "${id}"
version     = "0.1.0"
description = "${desc || "OPXDR endpoint telemetry agent"}"

[target]
os = [${(extras.targetOs || "linux,windows").split(",").map(s => `"${s.trim()}"`).join(", ")}]

[modules]
process_monitoring  = ${!!e.process_monitoring}
file_integrity      = ${!!e.file_integrity}
registry_monitoring = ${!!e.registry_monitoring}
etw_ebpf_collection = ${!!e.etw_ebpf}
memory_scanning     = ${!!e.memory_scanning}
local_detections    = ${!!e.local_detections}
secure_comms        = ${!!e.secure_comms}

[comms]
gateway_url     = "${extras.gatewayUrl || "https://gateway.opxdr:8443"}"
tls_verify      = true
heartbeat_secs  = ${parseInt(extras.heartbeat) || 30}
retry_backoff   = "exponential"
max_retry_delay = 300

[security]
sign_events       = true
encrypt_transport = true
rotate_key_hours  = 24
`;
}

export default function Registry() {
  const { customRules, setCustomRules } = useContext(OpxdrContext);
  const [filter, setFilter]       = useState("");
  const [expanded, setExpanded]   = useState(Object.keys(STATIC_REG));
  const [liveGroups, setLiveGroups] = useState({});
  const [showWriter, setShowWriter]   = useState(false);
  const [showAgentWriter, setShowAgentWriter] = useState(false);
  const [testfireRule, setTestfireRule] = useState(null);
  const [editRule, setEditRule] = useState(null);

  useEffect(() => {
    api("/api/rules").then(j => {
      if (j.groups) setLiveGroups(j.groups);
    }).catch(() => {});
  }, []);

  const fl = filter.toLowerCase();
  const fullReg = { ...STATIC_REG };
  for (const [k, g] of Object.entries(liveGroups)) {
    if (fullReg[k]) {
      const existingIds = new Set(fullReg[k].rules.map(r => r.id));
      const newRules = (g.rules || []).filter(r => !existingIds.has(r.id));
      if (newRules.length) fullReg[k] = { ...fullReg[k], rules: [...fullReg[k].rules, ...newRules] };
    } else {
      fullReg[k] = { label: g.label || k, color: g.color || "#64748b", icon: g.icon || "📂", rules: g.rules || [] };
    }
  }
  if (customRules.length > 0) {
    fullReg.custom = { label: "Custom Rules (Authored)", color: "#22c55e", icon: "📝", rules: customRules, isCustomGroup: true };
  }

  function handleSaveRule(rule) {
    setCustomRules([...customRules, rule]);
    setShowWriter(false);
  }

  function handleEditRuleSaved(rule) {
    setCustomRules(prev => {
      const idx = prev.findIndex(r => r.id === rule.id || r.wazuhRuleId === rule.wazuhRuleId);
      if (idx === -1) return [...prev, rule];
      const next = [...prev];
      next[idx] = rule;
      return next;
    });
    setEditRule(null);
  }

  return (
    <div className="p-5">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-xl font-extrabold text-ink-0 flex items-center gap-2">
            <BookOpen size={20} className="text-brand-accent" /> Detection Registry
          </h1>
          <p className="text-2xs text-ink-3 mt-0.5">
            {Object.values(STATIC_REG).reduce((s, g) => s + g.rules.length, 0)} static + {Object.values(liveGroups).reduce((s, g) => s + (g.rules?.length || 0), 0)} live · {customRules.length} custom
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-ink-3" />
            <input
              value={filter}
              onChange={e => setFilter(e.target.value)}
              placeholder="Search rules..."
              className="bg-bg-2 border border-border rounded-md pl-8 pr-3 py-1.5 text-xs text-ink-0 w-64 focus:border-brand outline-none"
            />
          </div>
          <button onClick={() => setShowAgentWriter(true)} className="btn btn-outline" style={{ borderColor: "#06b6d4", color: "#06b6d4" }}>
            <Plus size={14} /> New Agent
          </button>
          <button onClick={() => setShowWriter(true)} className="btn btn-brand">
            <Plus size={14} /> New Rule
          </button>
        </div>
      </div>

      <div className="space-y-3">
        {Object.entries(fullReg).map(([key, group]) => {
          const filt = filter
            ? group.rules.filter(r =>
                r.name.toLowerCase().includes(fl) ||
                r.tactic.toLowerCase().includes(fl) ||
                r.mitre.toLowerCase().includes(fl) ||
                r.id.toLowerCase().includes(fl)
              )
            : group.rules;
          if (filter && filt.length === 0) return null;
          const isOpen = expanded.includes(key);
          return (
            <div key={key} className="panel overflow-hidden">
              <div
                onClick={() => setExpanded(p => p.includes(key) ? p.filter(k => k !== key) : [...p, key])}
                className="px-4 py-3 flex items-center gap-3 cursor-pointer hover:bg-bg-2 border-b border-border"
                style={{ borderBottomColor: isOpen ? group.color + "33" : undefined }}
              >
                <span className="text-base">{group.icon}</span>
                <span className="text-sm font-bold tracking-wider" style={{ color: group.color }}>
                  {group.label}
                </span>
                <span className="text-2xs font-mono px-2 py-0.5 rounded" style={{ background: group.color + "20", color: group.color, border: `1px solid ${group.color}44` }}>
                  {filt.length} rules
                </span>
                <div className="ml-auto text-ink-3">
                  {isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                </div>
              </div>
              {isOpen && (
                <div className="divide-y divide-border">
                  {filt.map(rule => (
                    <RuleRow key={rule.id} rule={rule} groupColor={group.color} onConfigure={() => setTestfireRule(rule)} onEditRule={() => setEditRule(rule)} />
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {testfireRule && <TestfireModal rule={testfireRule} onClose={() => setTestfireRule(null)} />}
      {editRule && <RuleEditModal rule={editRule} onClose={() => setEditRule(null)} onSave={handleEditRuleSaved} />}
      {showWriter && <RuleWriter onClose={() => setShowWriter(false)} onSave={handleSaveRule} />}
      {showAgentWriter && <AgentWriter onClose={() => setShowAgentWriter(false)} />}
    </div>
  );
}

function RuleRow({ rule, groupColor, onConfigure, onEditRule }) {
  const [testing, setTesting] = useState(false);
  const [testStatus, setTestStatus] = useState(null);

  async function testFire() {
    setTesting(true);
    setTestStatus(null);
    try {
      const result = await api(`/api/rules/${encodeURIComponent(rule.wazuhRuleId || rule.id)}/testfire`, {
        method: "POST",
        body: JSON.stringify({ rule }),
      });
      setTestStatus(result.mode === "command" ? "fired" : "simulated");
    } catch (e) {
      console.warn("Rule testfire failed:", e);
      setTestStatus("failed");
    } finally {
      setTesting(false);
    }
  }

  const statusTitle =
    testStatus === "fired" ? "Testfire command completed" :
    testStatus === "simulated" ? "Simulated alert injected" :
    testStatus === "failed" ? "Testfire failed" :
    "Run testfire for this rule";

  return (
    <div className="px-4 py-2.5 grid grid-cols-12 gap-3 items-center hover:bg-bg-2">
      <code className="col-span-1 text-2xs font-mono truncate" style={{ color: groupColor }}>{rule.id}</code>
      <div className="col-span-4 min-w-0">
        <div className="text-xs font-semibold text-ink-0 flex items-center gap-1.5 min-w-0">
          <span className="truncate">{rule.name}</span>
          {rule.isCustom && <span className="badge badge-low text-3xs shrink-0">CUSTOM</span>}
        </div>
        <div className="text-3xs text-ink-3 font-mono mt-0.5 truncate">{rule.file}</div>
      </div>
      <span className="col-span-2 badge badge-info truncate" style={{ background: "transparent", color: groupColor, borderColor: groupColor + "44" }}>
        {rule.tactic}
      </span>
      <code className="col-span-2 text-2xs text-ink-3 font-mono truncate">{rule.mitre}</code>
      <div className="col-span-3 flex items-center justify-end gap-2 min-w-0">
        <span className={`badge ${
          rule.severity === "CRITICAL" ? "badge-critical" :
          rule.severity === "HIGH" ? "badge-high" :
          rule.severity === "MEDIUM" ? "badge-medium" : "badge-low"
        }`}>
          {rule.severity}
        </span>
        <button
          type="button"
          onClick={testFire}
          disabled={testing}
          title={statusTitle}
          className={`btn text-2xs px-2 py-1 disabled:opacity-50 ${testStatus === "failed" ? "btn-ghost text-bad" : "btn-outline"}`}
          style={testStatus && testStatus !== "failed" ? { borderColor: groupColor + "66", color: groupColor } : undefined}
        >
          <PlayCircle size={12} />
          {testing ? "Running" : testStatus === "fired" ? "Fired" : testStatus === "simulated" ? "Sent" : "Test"}
        </button>
        <button type="button" onClick={onConfigure} title="Edit testfire command" className="btn btn-ghost text-2xs px-2 py-1">
          <Copy size={12} /> Testfire
        </button>
        <button type="button" onClick={onEditRule} title="Edit detection rule" className="btn btn-ghost text-2xs px-2 py-1">
          <FileText size={12} /> Rule
        </button>
      </div>
    </div>
  );
}



function RuleEditModal({ rule, onClose, onSave }) {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(null);
  const [form, setForm] = useState({
    ruleId: String(rule.wazuhRuleId || rule.id || "").replace(/^(LOC|WAZ|CUS)-/, ""),
    name: rule.name || "",
    severity: rule.severity || "HIGH",
    tactic: rule.tactic || "Defense Evasion",
    mitre: rule.mitre === "-" || rule.mitre === "—" ? "" : (rule.mitre || ""),
    group: rule.group || "custom_detection",
    format: rule.format || (String(rule.file || "").match(/\.ya?ra$/i) ? "yara" : String(rule.file || "").match(/\.ya?ml$/i) ? "sigma" : "xml"),
    content: rule.xmlContent || rule.raw || "",
    savePath: rule.savePath || RULE_SAVE_PATHS[0].path,
  });

  const ruleKey = encodeURIComponent(rule.wazuhRuleId || rule.id);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    api(`/api/rules/${ruleKey}`).then((j) => {
      if (!alive) return;
      setForm(prev => ({
        ...prev,
        ruleId: String(j.wazuhRuleId || j.id || prev.ruleId).replace(/^(LOC|WAZ|CUS)-/, ""),
        name: j.name || prev.name,
        severity: j.severity || prev.severity,
        tactic: j.tactic || prev.tactic,
        mitre: j.mitre === "-" || j.mitre === "—" ? "" : (j.mitre || prev.mitre),
        group: j.group || prev.group,
        content: j.raw || prev.content,
      }));
    }).catch(() => {
      if (!alive) return;
      setForm(prev => ({ ...prev, content: prev.content || buildEditableRule(prev) }));
    }).finally(() => alive && setLoading(false));
    return () => { alive = false; };
  }, [ruleKey]);

  function update(k, v) {
    setForm(prev => ({ ...prev, [k]: v }));
  }

  function buildEditableRule(f) {
    const id = String(f.ruleId || rule.wazuhRuleId || rule.id || "200000").replace(/\D/g, "") || "200000";
    const level = f.severity === "CRITICAL" ? "14" : f.severity === "HIGH" ? "12" : f.severity === "MEDIUM" ? "8" : "4";
    const group = f.group || "custom_detection";
    const mitre = (f.mitre || "").split(",").map(x => x.trim()).filter(Boolean).map(x => `<id>${x}</id>`).join("");
    return `<group name="${group},opxdr,custom,">
  <rule id="${id}" level="${level}">
    <match>OPXDR_CUSTOM_RULE_${id}</match>
    <description>${f.name || rule.name || `Edited rule ${id}`}</description>
    <group>${group},${String(f.tactic || "").toLowerCase().replace(/\s+/g, "_")},</group>${mitre ? `\n    <mitre>${mitre}</mitre>` : ""}
  </rule>
</group>`;
  }

  async function save() {
    setSaving(true);
    setError("");
    setSaved(null);
    try {
      const content = form.content.trim() || buildEditableRule(form);
      const response = await api("/api/rules/custom", {
        method: "POST",
        body: JSON.stringify({
          ruleId: form.ruleId,
          name: form.name,
          severity: form.severity,
          tactic: form.tactic,
          mitre: form.mitre,
          group: form.group,
          xml: content,
          savePath: form.savePath,
          format: form.format,
        }),
      });
      const savedRule = {
        ...rule,
        id: `CUS-${form.ruleId}`,
        wazuhRuleId: form.ruleId,
        name: form.name,
        severity: form.severity,
        tactic: form.tactic,
        mitre: form.mitre || "-",
        group: form.group,
        file: response.saved?.custom?.split("/").pop() || rule.file,
        xmlContent: content,
        isCustom: true,
        format: form.format,
        savePath: form.savePath,
      };
      setSaved(response);
      onSave(savedRule);
    } catch (e) {
      setError(e.message || String(e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="fixed inset-0 bg-black/85 flex items-center justify-center z-50 p-4">
      <div className="bg-bg-1 border border-ok/40 rounded-xl w-full max-w-5xl max-h-[94vh] flex flex-col overflow-hidden">
        <div className="px-5 py-3 border-b border-border flex items-center justify-between shrink-0">
          <div>
            <div className="text-sm font-extrabold text-ok tracking-wider">EDIT DETECTION RULE</div>
            <div className="text-3xs text-ink-3 font-mono">{rule.id} - {rule.name}</div>
          </div>
          <button onClick={onClose} className="btn btn-ghost"><X size={14} /></button>
        </div>

        <div className="p-5 space-y-4 overflow-y-auto">
          {loading ? <div className="text-xs text-ink-3 font-mono">Loading rule...</div> : null}
          {error ? <div className="border border-bad/40 bg-bad/10 text-bad text-xs rounded-md px-3 py-2 font-mono">{error}</div> : null}
          {saved ? (
            <div className={`border text-xs rounded-md px-3 py-2 font-mono ${saved.wazuh_error || saved.restart_error ? "border-sev-medium/40 bg-sev-medium/10 text-sev-medium" : "border-ok/40 bg-ok/10 text-ok"}`}>
              {saved.wazuh_error || saved.restart_error ? `Saved custom rule copy. Wazuh warning: ${saved.wazuh_error || saved.restart_error}` : "Saved custom rule copy and refreshed Wazuh."}
            </div>
          ) : null}

          <div className="grid grid-cols-12 gap-3">
            <label className="col-span-2"><div className="text-3xs text-ink-3 font-mono mb-1">Rule ID</div><input value={form.ruleId} onChange={e => update("ruleId", e.target.value)} className="w-full bg-bg-0 border border-border rounded-md px-3 py-2 text-xs text-ink-1 font-mono outline-none focus:border-brand" /></label>
            <label className="col-span-4"><div className="text-3xs text-ink-3 font-mono mb-1">Name</div><input value={form.name} onChange={e => update("name", e.target.value)} className="w-full bg-bg-0 border border-border rounded-md px-3 py-2 text-xs text-ink-1 outline-none focus:border-brand" /></label>
            <label className="col-span-2"><div className="text-3xs text-ink-3 font-mono mb-1">Severity</div><select value={form.severity} onChange={e => update("severity", e.target.value)} className="w-full bg-bg-0 border border-border rounded-md px-3 py-2 text-xs text-ink-1 outline-none focus:border-brand"><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select></label>
            <label className="col-span-2"><div className="text-3xs text-ink-3 font-mono mb-1">Format</div><select value={form.format} onChange={e => update("format", e.target.value)} className="w-full bg-bg-0 border border-border rounded-md px-3 py-2 text-xs text-ink-1 outline-none focus:border-brand"><option value="xml">Wazuh XML</option><option value="sigma">Sigma YAML</option><option value="yara">YARA</option></select></label>
            <label className="col-span-2"><div className="text-3xs text-ink-3 font-mono mb-1">Group</div><input value={form.group} onChange={e => update("group", e.target.value)} className="w-full bg-bg-0 border border-border rounded-md px-3 py-2 text-xs text-ink-1 font-mono outline-none focus:border-brand" /></label>
          </div>

          <div className="grid grid-cols-12 gap-3">
            <label className="col-span-4"><div className="text-3xs text-ink-3 font-mono mb-1">Tactic</div><select value={form.tactic} onChange={e => update("tactic", e.target.value)} className="w-full bg-bg-0 border border-border rounded-md px-3 py-2 text-xs text-ink-1 outline-none focus:border-brand">{TACTIC_LIST.map(t => <option key={t}>{t}</option>)}</select></label>
            <label className="col-span-4"><div className="text-3xs text-ink-3 font-mono mb-1">MITRE</div><input value={form.mitre} onChange={e => update("mitre", e.target.value)} placeholder="T1059,T1027" className="w-full bg-bg-0 border border-border rounded-md px-3 py-2 text-xs text-ink-1 font-mono outline-none focus:border-brand" /></label>
            <label className="col-span-4"><div className="text-3xs text-ink-3 font-mono mb-1">Save Path</div><select value={form.savePath} onChange={e => update("savePath", e.target.value)} className="w-full bg-bg-0 border border-border rounded-md px-3 py-2 text-xs text-ink-1 font-mono outline-none focus:border-brand">{RULE_SAVE_PATHS.filter(p => p.path !== "__custom__").map(p => <option key={p.path} value={p.path}>{p.label}</option>)}</select></label>
          </div>

          <div>
            <div className="text-3xs text-ink-3 font-mono uppercase tracking-wider mb-1">Rule Content</div>
            <textarea value={form.content} onChange={e => update("content", e.target.value)} rows={18} className="w-full bg-bg-0 border border-border rounded-md px-3 py-2 text-xs text-ink-1 font-mono outline-none focus:border-brand" />
          </div>
        </div>

        <div className="px-5 py-3 border-t border-border flex items-center justify-between shrink-0">
          <button type="button" onClick={() => navigator.clipboard?.writeText(form.content)} className="btn btn-outline"><Copy size={14} /> Copy</button>
          <div className="flex items-center gap-2">
            <button type="button" onClick={onClose} className="btn btn-ghost">Close</button>
            <button type="button" onClick={save} disabled={saving || !form.ruleId || !form.name} className="btn btn-brand disabled:opacity-40">
              <FileText size={14} /> {saving ? "Saving..." : "Save Rule"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function TestfireModal({ rule, onClose }) {
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [command, setCommand] = useState("");
  const [argsText, setArgsText] = useState("");
  const [payloadText, setPayloadText] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const ruleKey = encodeURIComponent(rule.wazuhRuleId || rule.id);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError("");
    api(`/api/rules/${ruleKey}/testfire`).then((j) => {
      if (!alive) return;
      setCommand(j.command?.command || "");
      setArgsText((j.command?.args || []).join("\n"));
      setPayloadText(JSON.stringify({ ...rule, ...(j.rulePayload || {}) }, null, 2));
    }).catch((e) => {
      if (alive) setError(e.message || String(e));
    }).finally(() => alive && setLoading(false));
    return () => { alive = false; };
  }, [ruleKey]);

  function argsFromText() {
    return argsText.split("\n").map(s => s.trim()).filter(Boolean);
  }

  async function runEdited() {
    setRunning(true);
    setError("");
    setResult(null);
    try {
      const rulePayload = JSON.parse(payloadText);
      const j = await api(`/api/rules/${ruleKey}/testfire`, {
        method: "POST",
        body: JSON.stringify({ command, args: argsFromText(), rulePayload }),
      });
      setResult(j);
    } catch (e) {
      setError(e.message || String(e));
    } finally {
      setRunning(false);
    }
  }

  const fullCommand = `${command} ${argsFromText().map(a => /\s/.test(a) ? JSON.stringify(a) : a).join(" ")}`.trim();

  return (
    <div className="fixed inset-0 bg-black/85 flex items-center justify-center z-50 p-4">
      <div className="bg-bg-1 border border-brand/40 rounded-xl w-full max-w-4xl max-h-[92vh] flex flex-col overflow-hidden">
        <div className="px-5 py-3 border-b border-border flex items-center justify-between shrink-0">
          <div>
            <div className="text-sm font-extrabold text-brand-accent tracking-wider">TESTFIRE COMMAND</div>
            <div className="text-3xs text-ink-3 font-mono">{rule.id} - {rule.name}</div>
          </div>
          <button onClick={onClose} className="btn btn-ghost"><X size={14} /></button>
        </div>

        <div className="p-5 space-y-4 overflow-y-auto">
          {loading ? <div className="text-xs text-ink-3 font-mono">Loading testfire command...</div> : null}
          {error ? <div className="border border-bad/40 bg-bad/10 text-bad text-xs rounded-md px-3 py-2 font-mono">{error}</div> : null}

          <div>
            <div className="text-3xs text-ink-3 font-mono uppercase tracking-wider mb-1">Command</div>
            <input value={command} onChange={e => setCommand(e.target.value)} className="w-full bg-bg-0 border border-border rounded-md px-3 py-2 text-xs text-ink-1 font-mono outline-none focus:border-brand" />
          </div>

          <div>
            <div className="text-3xs text-ink-3 font-mono uppercase tracking-wider mb-1">Arguments (one per line)</div>
            <textarea value={argsText} onChange={e => setArgsText(e.target.value)} rows={5} className="w-full bg-bg-0 border border-border rounded-md px-3 py-2 text-xs text-ink-1 font-mono outline-none focus:border-brand" />
          </div>

          <div>
            <div className="text-3xs text-ink-3 font-mono uppercase tracking-wider mb-1">Rule Payload / Test Vector Context</div>
            <textarea value={payloadText} onChange={e => setPayloadText(e.target.value)} rows={12} className="w-full bg-bg-0 border border-border rounded-md px-3 py-2 text-xs text-ink-1 font-mono outline-none focus:border-brand" />
          </div>

          <div className="bg-bg-0 border border-border rounded-md px-3 py-2 text-2xs text-ink-2 font-mono break-all">
            {fullCommand}
          </div>

          {result ? (
            <div className="space-y-2">
              <div className="text-3xs text-ok font-mono uppercase tracking-wider">Last Run Result</div>
              <pre className="bg-bg-0 border border-border rounded-md p-3 text-2xs text-ink-2 overflow-auto max-h-56">{JSON.stringify(result, null, 2)}</pre>
            </div>
          ) : null}
        </div>

        <div className="px-5 py-3 border-t border-border flex items-center justify-between shrink-0">
          <button type="button" onClick={() => navigator.clipboard?.writeText(fullCommand)} className="btn btn-outline"><Copy size={14} /> Copy</button>
          <div className="flex items-center gap-2">
            <button type="button" onClick={onClose} className="btn btn-ghost">Close</button>
            <button type="button" onClick={runEdited} disabled={running || loading} className="btn btn-brand disabled:opacity-40">
              <PlayCircle size={14} /> {running ? "Running..." : "Run Testfire"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── RULE WRITER MODAL ────────────────────────────────────────────────────────
const TABS = [
  { id: "build",    label: "📝 Build + AI" },
  { id: "ir",       label: "🚨 IR Playbook" },
  { id: "output",   label: "</> Output" },
  { id: "preview",  label: "👁 Preview" },
];

function RuleWriter({ onClose, onSave }) {
  const newId = String(200000 + Math.floor(Math.random() * 9000));
  const [tab, setTab]     = useState("build");
  const [format, setFormat] = useState("xml");
  const [saving, setSaving] = useState(false);
  const [savePathKey, setSavePathKey] = useState(RULE_SAVE_PATHS[0].path);
  const [customPath, setCustomPath]   = useState("");

  const [f, setF] = useState({
    ruleId: newId,
    level: "12",
    severity: "HIGH",
    description: "",
    groupName: "custom_detection",
    decoderAs: "json",
    tactic: "Initial Access",
    mitreTechniques: ["T1078", ""],
    fieldConditions: [{ name: "", value: "", negate: false }, { name: "", value: "", negate: false }],
  });

  // IR Playbook state (editable YAML)
  const [irContent, setIrContent] = useState("");
  const [irGenerated, setIrGenerated] = useState(false);

  function sf(k, v) {
    setF(p => ({ ...p, [k]: v, severity: k === "level" ? sevFromLevel(v) : p.severity }));
  }

  const resolvedPath = savePathKey === "__custom__" ? customPath : savePathKey;

  const xml    = buildXML(f);
  const sigma  = buildSigma(f);
  const yara   = buildYARA(f);
  const outputContent = format === "sigma" ? sigma : format === "yara" ? yara : xml;
  const fileExt       = format === "sigma" ? "yml" : format === "yara" ? "yar" : "xml";

  // Auto-generate IR playbook when user switches to IR tab for first time
  function ensureIR() {
    if (!irGenerated) {
      setIrContent(buildIRPlaybook(f));
      setIrGenerated(true);
    }
  }

  async function save() {
    setSaving(true);
    const rule = {
      id: `CUS-${f.ruleId}`,
      file: `custom_${new Date().toISOString().slice(0, 10).replace(/-/g, "")}.${fileExt}`,
      name: f.description || `Custom Rule ${f.ruleId}`,
      tactic: f.tactic,
      mitre: f.mitreTechniques.filter(Boolean).join(","),
      severity: f.severity,
      wazuhRuleId: f.ruleId,
      level: parseInt(f.level),
      isCustom: true,
      xmlContent: outputContent,
      format,
      savePath: resolvedPath,
    };
    try {
      await fetch("/api/rules/custom", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ruleId: f.ruleId,
          name: rule.name,
          severity: f.severity,
          tactic: f.tactic,
          mitre: rule.mitre,
          group: f.groupName,
          xml: outputContent,
          yaml: irContent || undefined,
          savePath: resolvedPath,
          format,
        }),
      });
    } catch (e) {
      console.warn("Backend save failed:", e);
    }
    onSave(rule);
    setSaving(false);
  }

  return (
    <div className="fixed inset-0 bg-black/85 flex items-center justify-center z-50 p-4">
      <div className="bg-bg-1 border border-ok/40 rounded-xl w-full max-w-5xl max-h-[95vh] flex flex-col overflow-hidden">

        {/* Header */}
        <div className="px-5 py-3 border-b border-border flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <span className="text-xl">📝</span>
            <div>
              <div className="text-sm font-extrabold text-ok tracking-wider">RULE WRITER</div>
              <div className="text-3xs text-ink-3 font-mono">Author detection rules · YARA / Sigma / Wazuh XML</div>
            </div>
            <span className={`badge ${f.severity === "CRITICAL" ? "badge-critical" : f.severity === "HIGH" ? "badge-high" : "badge-medium"}`}>
              {f.severity}
            </span>
          </div>
          <div className="flex gap-2 items-center">
            {/* Format selector */}
            <div className="flex items-center gap-1 bg-bg-2 border border-border rounded-md px-1 py-0.5">
              {["xml", "sigma", "yara"].map(fmt => (
                <button
                  key={fmt}
                  onClick={() => setFormat(fmt)}
                  className={`px-2.5 py-1 text-3xs font-mono font-bold rounded transition-colors ${
                    format === fmt ? "bg-brand text-white" : "text-ink-3 hover:text-ink-1"
                  }`}
                >
                  {fmt.toUpperCase()}
                </button>
              ))}
            </div>
            <button onClick={save} disabled={!f.description || saving} className="btn btn-brand disabled:opacity-40">
              {saving ? "Saving..." : "✓ Save & Register"}
            </button>
            <button onClick={onClose} className="btn btn-ghost">
              <X size={14} />
            </button>
          </div>
        </div>

        {/* Save path row */}
        <div className="px-5 py-2 border-b border-border bg-bg-2 flex items-center gap-3 shrink-0">
          <span className="text-3xs text-ink-3 font-mono uppercase tracking-wider whitespace-nowrap">Save to:</span>
          <select
            value={savePathKey}
            onChange={e => setSavePathKey(e.target.value)}
            className="bg-bg-0 border border-border rounded px-2 py-1 text-xs font-mono text-ink-1 focus:border-brand outline-none flex-1 max-w-xs"
          >
            {RULE_SAVE_PATHS.map(p => (
              <option key={p.path} value={p.path}>{p.label}</option>
            ))}
          </select>
          {savePathKey === "__custom__" ? (
            <input
              value={customPath}
              onChange={e => setCustomPath(e.target.value)}
              placeholder="/absolute/path/to/rules"
              className="bg-bg-0 border border-border rounded px-2 py-1 text-xs font-mono text-ink-0 focus:border-brand outline-none flex-1"
            />
          ) : (
            <code className="text-3xs text-ink-3 font-mono truncate">{savePathKey}</code>
          )}
        </div>

        {/* Tab bar */}
        <div className="flex border-b border-border bg-bg-2 shrink-0">
          {TABS.map(t => (
            <button
              key={t.id}
              onClick={() => { setTab(t.id); if (t.id === "ir") ensureIR(); }}
              className={`px-5 py-2.5 text-xs font-mono font-semibold transition-colors ${
                tab === t.id ? "border-b-2 border-ok text-ok" : "text-ink-3 hover:text-ink-1"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* Tab content — build tab gets full split layout, others get scrollable container */}
        {tab === "build" ? (
          <BuildTab f={f} sf={sf} setF={setF} format={format} />
        ) : (
          <div className="flex-1 overflow-y-auto p-5">
            {tab === "ir" && (
              <IRPlaybookTab content={irContent} setContent={setIrContent} f={f} onRegenerate={() => { setIrContent(buildIRPlaybook(f)); }} />
            )}
            {tab === "output" && (
              <OutputTab content={outputContent} format={format} />
            )}
            {tab === "preview" && (
              <PreviewTab f={f} outputContent={outputContent} irContent={irContent} format={format} />
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── BUILD TAB (form + AI assist side-by-side) ───────────────────────────────
function BuildTab({ f, sf, setF, format }) {
  return (
    <div className="flex flex-1 overflow-hidden" style={{ minHeight: 0 }}>
      {/* Left — form fields */}
      <div className="w-[42%] shrink-0 border-r border-border overflow-y-auto p-5 space-y-3">
        <div className="text-3xs text-ink-3 font-mono uppercase tracking-wider mb-3 flex items-center gap-2">
          <span className="text-ok">●</span> Rule Fields
        </div>
        <Field label="Rule ID">
          <input value={f.ruleId} onChange={e => sf("ruleId", e.target.value)} className={inputCls} />
        </Field>
        <Field label="Level (1-15)">
          <input type="number" min="1" max="15" value={f.level} onChange={e => sf("level", e.target.value)} className={inputCls} />
        </Field>
        <Field label="Description *">
          <input value={f.description} onChange={e => sf("description", e.target.value)} placeholder="Suspicious network logon..." className={inputCls} />
        </Field>
        <Field label="Group Name">
          <input value={f.groupName} onChange={e => sf("groupName", e.target.value)} className={inputCls} />
        </Field>
        {format === "xml" && (
          <Field label="Decoder">
            <select value={f.decoderAs} onChange={e => sf("decoderAs", e.target.value)} className={inputCls}>
              {["json", "syslog", "windows_eventchannel", "auditd", "ssh", "nginx", "apache", "suricata"].map(d => (
                <option key={d}>{d}</option>
              ))}
            </select>
          </Field>
        )}
        <Field label="Tactic">
          <select value={f.tactic} onChange={e => sf("tactic", e.target.value)} className={inputCls}>
            {TACTIC_LIST.map(t => <option key={t}>{t}</option>)}
          </select>
        </Field>
        <Field label="MITRE Techniques">
          {f.mitreTechniques.map((m, i) => (
            <div key={i} className="flex gap-2 mb-1.5">
              <select
                value={m}
                onChange={e => {
                  const arr = [...f.mitreTechniques];
                  arr[i] = e.target.value;
                  setF(p => ({ ...p, mitreTechniques: arr }));
                }}
                className={inputCls + " flex-1"}
              >
                <option value="">— select —</option>
                {MITRE_OPTS.map(o => <option key={o}>{o}</option>)}
              </select>
            </div>
          ))}
          <button
            onClick={() => setF(p => ({ ...p, mitreTechniques: [...p.mitreTechniques, ""] }))}
            className="text-3xs text-brand hover:text-brand/80 font-mono mt-1"
          >
            + Add technique
          </button>
        </Field>
        <Field label={format === "yara" ? "String Patterns (label → regex)" : "Field Conditions"}>
          {f.fieldConditions.map((fc, i) => (
            <div key={i} className="grid grid-cols-[1fr_1fr_auto] gap-1.5 mb-1.5">
              <input
                value={fc.name}
                onChange={e => {
                  const arr = [...f.fieldConditions];
                  arr[i] = { ...arr[i], name: e.target.value };
                  setF(p => ({ ...p, fieldConditions: arr }));
                }}
                placeholder={format === "yara" ? "label" : "field"}
                className={inputCls}
              />
              <input
                value={fc.value}
                onChange={e => {
                  const arr = [...f.fieldConditions];
                  arr[i] = { ...arr[i], value: e.target.value };
                  setF(p => ({ ...p, fieldConditions: arr }));
                }}
                placeholder="regex / pattern"
                className={inputCls}
              />
              <button
                onClick={() => {
                  const arr = [...f.fieldConditions];
                  arr[i] = { ...arr[i], negate: !arr[i].negate };
                  setF(p => ({ ...p, fieldConditions: arr }));
                }}
                className={`px-2 py-1 rounded border text-2xs font-mono ${fc.negate ? "bg-bad/20 border-bad text-bad" : "border-border text-ink-3"}`}
              >
                {fc.negate ? "NOT" : "="}
              </button>
            </div>
          ))}
          <button
            onClick={() => setF(p => ({ ...p, fieldConditions: [...p.fieldConditions, { name: "", value: "", negate: false }] }))}
            className="text-3xs text-brand hover:text-brand/80 font-mono mt-1"
          >
            + Add condition
          </button>
        </Field>
      </div>

      {/* Right — AI assist */}
      <div className="flex-1 flex flex-col p-5 overflow-hidden" style={{ minHeight: 0 }}>
        <div className="text-3xs text-ink-3 font-mono uppercase tracking-wider mb-3 flex items-center gap-2">
          <span className="text-brand">●</span> AI Assist — OpenCode Zen
        </div>
        <AIAssistTab f={f} format={format} />
      </div>
    </div>
  );
}

// ─── AI ASSIST TAB ───────────────────────────────────────────────────────────
const AI_SYSTEM = `You are a senior detection engineer assistant integrated into the OPXDR SOC platform.
You help analysts write detection rules in Wazuh XML, Sigma YAML, and YARA formats.
You know MITRE ATT&CK, Wazuh rule syntax, Sigma specification, and YARA rule syntax.
Give concise, accurate answers. When writing rules, produce complete, valid rule syntax.
Always include MITRE technique IDs and explain the detection logic.`;

function AIAssistTab({ f, format }) {
  const [messages, setMessages]   = useState([]);
  const [input, setInput]         = useState("");
  const [streaming, setStreaming] = useState(false);
  const bottomRef = useRef(null);
  const inputRef  = useRef(null);

  // Pre-fill context about current rule
  const ruleContext = `Current rule context: ID=${f.ruleId}, Description="${f.description || "(none yet)"}", Tactic="${f.tactic}", Format=${format.toUpperCase()}, MITRE=[${f.mitreTechniques.filter(Boolean).join(", ")}]`;

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  async function sendMessage(text) {
    if (!text.trim() || streaming) return;
    const userMsg = { role: "user", content: text };
    const newHistory = [...messages, userMsg];
    setMessages([...newHistory, { role: "assistant", content: "..." }]);
    setInput("");
    setStreaming(true);

    const systemCtx = `${AI_SYSTEM}\n\n${ruleContext}`;
    let full = "";
    try {
      await callAgent(
        "ruleAssistant",
        newHistory,
        (chunk) => {
          full = chunk;
          setMessages([...newHistory, { role: "assistant", content: chunk }]);
        },
        { system: systemCtx }
      );
    } catch (e) {
      full = `[Error: ${e.message}]`;
      setMessages([...newHistory, { role: "assistant", content: full }]);
    }
    setStreaming(false);
    inputRef.current?.focus();
  }

  const quickPrompts = [
    `Write a ${format.toUpperCase()} rule to detect: ${f.description || "suspicious login"}`,
    `What MITRE techniques should I add for ${f.tactic}?`,
    `Review my field conditions for false positive risk`,
    `Generate YARA strings for common ${f.tactic.toLowerCase()} patterns`,
    `How do I tune this rule to reduce noise?`,
  ];

  return (
    <div className="flex flex-col h-full min-h-[420px]">
      {/* Quick prompts */}
      {messages.length === 0 && (
        <div className="mb-4">
          <div className="text-3xs text-ink-3 font-mono uppercase tracking-wider mb-2">Quick prompts — powered by OpenCode Zen</div>
          <div className="flex flex-wrap gap-2">
            {quickPrompts.map((p, i) => (
              <button
                key={i}
                onClick={() => sendMessage(p)}
                className="text-3xs bg-bg-2 border border-border hover:border-brand text-ink-2 hover:text-ink-0 px-2.5 py-1.5 rounded font-mono transition-colors text-left"
              >
                {p}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Message thread */}
      <div className="flex-1 overflow-y-auto space-y-3 mb-3 min-h-[200px]">
        {messages.map((m, i) => (
          <div key={i} className={`flex gap-2.5 ${m.role === "user" ? "justify-end" : "justify-start"}`}>
            {m.role === "assistant" && (
              <div className="w-6 h-6 rounded-full bg-brand/20 border border-brand/40 flex items-center justify-center text-xs shrink-0 mt-0.5">🤖</div>
            )}
            <div className={`max-w-[80%] rounded-lg px-3 py-2 text-xs font-mono whitespace-pre-wrap ${
              m.role === "user"
                ? "bg-brand/20 border border-brand/30 text-ink-0"
                : "bg-bg-2 border border-border text-ink-1"
            }`}>
              {m.content}
              {m.role === "assistant" && streaming && i === messages.length - 1 && (
                <span className="inline-block w-1.5 h-3 bg-ok ml-1 animate-pulse" />
              )}
            </div>
            {m.role === "user" && (
              <div className="w-6 h-6 rounded-full bg-ok/20 border border-ok/40 flex items-center justify-center text-xs shrink-0 mt-0.5">👤</div>
            )}
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div className="flex gap-2 items-end">
        <textarea
          ref={inputRef}
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => {
            if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(input); }
          }}
          placeholder="Ask the AI to help write, review, or improve your detection rule..."
          disabled={streaming}
          rows={2}
          className="flex-1 bg-bg-0 border border-border rounded-md px-3 py-2 text-xs font-mono text-ink-0 focus:border-brand outline-none resize-none disabled:opacity-50"
        />
        <button
          onClick={() => sendMessage(input)}
          disabled={!input.trim() || streaming}
          className="btn btn-brand disabled:opacity-40 shrink-0"
        >
          <Send size={13} />
        </button>
      </div>
      <div className="text-3xs text-ink-3 font-mono mt-1.5">
        Uses OpenCode Zen (OCZ_API_KEY) · ruleAssistant agent · Shift+Enter for newline
      </div>
    </div>
  );
}

// ─── IR PLAYBOOK TAB ─────────────────────────────────────────────────────────
function IRPlaybookTab({ content, setContent, f, onRegenerate }) {
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-xs font-bold text-ink-0">Incident Response Playbook</div>
          <div className="text-3xs text-ink-3 font-mono">YAML playbook auto-generated from rule metadata. Edit as needed.</div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={onRegenerate}
            className="btn btn-outline text-3xs"
          >
            ↻ Regenerate
          </button>
          <button
            onClick={() => navigator.clipboard?.writeText(content)}
            className="btn btn-outline"
          >
            <Copy size={12} /> Copy
          </button>
        </div>
      </div>
      <textarea
        value={content}
        onChange={e => setContent(e.target.value)}
        className="w-full bg-bg-0 border border-border rounded-md p-4 text-xs text-ink-1 font-mono focus:border-brand outline-none resize-none"
        rows={28}
        spellCheck={false}
      />
    </div>
  );
}

// ─── OUTPUT TAB ──────────────────────────────────────────────────────────────
function OutputTab({ content, format }) {
  const label = format === "sigma" ? "Sigma YAML" : format === "yara" ? "YARA Rule" : "Wazuh XML";
  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <span className="panel-title">{label} — Generated Output</span>
        <button onClick={() => navigator.clipboard?.writeText(content)} className="btn btn-outline">
          <Copy size={12} /> Copy
        </button>
      </div>
      <pre className="bg-bg-0 border border-border rounded-md p-4 text-xs text-ink-1 font-mono overflow-auto whitespace-pre-wrap">
        {content}
      </pre>
    </div>
  );
}

// ─── PREVIEW TAB ─────────────────────────────────────────────────────────────
function PreviewTab({ f, outputContent, irContent, format }) {
  return (
    <div className="space-y-4">
      {/* Rule card */}
      <div className="panel p-4">
        <div className="flex items-center gap-2 mb-3">
          <span className="text-3xs text-ink-3 font-mono uppercase tracking-wider">
            {format.toUpperCase()} RULE PREVIEW
          </span>
          <span className={`badge ${f.severity === "CRITICAL" ? "badge-critical" : f.severity === "HIGH" ? "badge-high" : f.severity === "MEDIUM" ? "badge-medium" : "badge-low"}`}>
            {f.severity}
          </span>
        </div>
        <div className="text-sm font-bold text-ink-0 mb-2">{f.description || "<description>"}</div>
        <div className="grid grid-cols-3 gap-2 text-xs text-ink-2 font-mono mb-3">
          <div><span className="text-ink-3">rule_id:</span> {f.ruleId}</div>
          <div><span className="text-ink-3">level:</span> {f.level}</div>
          <div><span className="text-ink-3">format:</span> {format.toUpperCase()}</div>
          <div><span className="text-ink-3">tactic:</span> {f.tactic}</div>
          <div><span className="text-ink-3">decoder:</span> {f.decoderAs}</div>
          <div><span className="text-ink-3">group:</span> {f.groupName}</div>
        </div>
        <div className="flex gap-1.5 flex-wrap mb-3">
          {f.mitreTechniques.filter(Boolean).map(t => (
            <code key={t} className="bg-bg-2 border border-border text-info px-1.5 py-0.5 rounded text-3xs font-mono">{t}</code>
          ))}
        </div>
        <details className="mt-2">
          <summary className="text-3xs text-ink-3 font-mono cursor-pointer hover:text-ink-1">View generated {format.toUpperCase()}</summary>
          <pre className="mt-2 bg-bg-0 border border-border rounded p-3 text-3xs text-ink-1 font-mono overflow-auto max-h-48 whitespace-pre-wrap">
            {outputContent}
          </pre>
        </details>
      </div>

      {/* IR Playbook card */}
      {irContent ? (
        <div className="panel p-4">
          <div className="flex items-center gap-2 mb-3">
            <span className="text-lg">🚨</span>
            <div>
              <div className="text-xs font-bold text-ink-0">Incident Response Playbook</div>
              <div className="text-3xs text-ink-3 font-mono">IR-{f.ruleId} — {f.description || "Custom Detection"}</div>
            </div>
            <span className={`ml-auto badge ${f.severity === "CRITICAL" ? "badge-critical" : f.severity === "HIGH" ? "badge-high" : "badge-medium"}`}>
              {f.severity}
            </span>
          </div>
          <div className="grid grid-cols-2 gap-3 mb-3">
            {[
              { icon: "🔍", title: "Triage", steps: ["Confirm alert validity", "Identify source host & user", "Check asset classification"] },
              { icon: "🔒", title: "Containment", steps: ["Isolate endpoint if needed", "Reset compromised credentials", "Block source IP at perimeter"] },
              { icon: "🧹", title: "Eradication", steps: ["Remove malicious artifacts", "Revoke exposed tokens", "Patch exploited vulnerability"] },
              { icon: "✅", title: "Recovery", steps: ["Restore from known-good backup", "Re-enable network access", "Monitor 72h post-recovery"] },
            ].map(s => (
              <div key={s.title} className="bg-bg-2 border border-border rounded-md p-3">
                <div className="text-3xs font-bold text-ink-2 mb-1.5 flex items-center gap-1.5">
                  <span>{s.icon}</span>{s.title}
                </div>
                <ul className="space-y-0.5">
                  {s.steps.map((step, i) => (
                    <li key={i} className="text-3xs text-ink-3 font-mono flex items-start gap-1">
                      <span className="text-ok mt-0.5">›</span>{step}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
          <details>
            <summary className="text-3xs text-ink-3 font-mono cursor-pointer hover:text-ink-1">View full YAML playbook</summary>
            <pre className="mt-2 bg-bg-0 border border-border rounded p-3 text-3xs text-ink-1 font-mono overflow-auto max-h-48 whitespace-pre-wrap">
              {irContent}
            </pre>
          </details>
        </div>
      ) : (
        <div className="panel p-4 border-dashed opacity-50">
          <div className="text-xs text-ink-3 font-mono text-center">
            Visit the IR Playbook tab to generate the incident response playbook
          </div>
        </div>
      )}
    </div>
  );
}

function Field({ label, children }) {
  return (
    <div>
      <label className="block text-3xs uppercase tracking-wider text-ink-3 font-mono mb-1.5">{label}</label>
      {children}
    </div>
  );
}

const inputCls = "w-full bg-bg-0 border border-border rounded-md px-3 py-1.5 text-xs text-ink-0 font-mono focus:border-brand outline-none";

// ─── AGENT WRITER MODAL ───────────────────────────────────────────────────────
const AGENT_TABS = [
  { id: "build",   label: "⚙️ Configure + AI" },
  { id: "preview", label: "👁 Preview" },
];

const COLOR = "#f97316"; // endpoint orange

function AgentWriter({ onClose }) {
  const [tab, setTab]         = useState("build");
  const [name, setName]       = useState("");
  const [desc, setDesc]       = useState("");
  const [mods, setMods]       = useState(() => ENDPOINT_AGENT.modules.map(m => ({ ...m })));
  const [extras, setExtras]   = useState({});
  const [saving, setSaving]   = useState(false);
  const [saved, setSaved]     = useState(false);

  function toggleMod(id) { setMods(p => p.map(m => m.id === id ? { ...m, on: !m.on } : m)); }
  function setExtra(k, v)  { setExtras(p => ({ ...p, [k]: v })); }

  const generatedConfig = buildAgentConfig(name, desc, mods, extras);
  const fileName = `${(name || "opxdr-endpoint").replace(/\s+/g, "-").toLowerCase()}.toml`;
  const serverOrigin = typeof window !== "undefined" ? window.location.origin : "http://localhost:8787";

  async function save() {
    setSaving(true);
    try {
      await fetch("/api/rules/custom", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ruleId: `AGENT-${Date.now()}`,
          name: name || "opxdr-endpoint",
          severity: "HIGH", tactic: "Defense", mitre: "",
          group: "agent_endpoint", xml: generatedConfig, format: "toml",
        }),
      });
    } catch {}
    setSaving(false); setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  }

  return (
    <div className="fixed inset-0 bg-black/85 flex items-center justify-center z-50 p-4">
      <div className="bg-bg-1 border rounded-xl w-full max-w-5xl max-h-[95vh] flex flex-col overflow-hidden"
           style={{ borderColor: COLOR + "60" }}>

        {/* Header */}
        <div className="px-5 py-3 border-b border-border flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <span className="text-xl">🖥️</span>
            <div>
              <div className="text-sm font-extrabold tracking-wider" style={{ color: COLOR }}>ENDPOINT AGENT WRITER</div>
              <div className="text-3xs text-ink-3 font-mono">Configure & deploy OPXDR endpoint agent</div>
            </div>
          </div>
          <div className="flex gap-2 items-center">
            <button onClick={save} disabled={saving}
              className="btn disabled:opacity-40"
              style={{ background: COLOR + "22", border: `1px solid ${COLOR}66`, color: COLOR }}>
              {saved ? "✓ Saved" : saving ? "Saving..." : "✓ Save Config"}
            </button>
            <button onClick={onClose} className="btn btn-ghost"><X size={14} /></button>
          </div>
        </div>

        {/* Tab bar */}
        <div className="flex border-b border-border bg-bg-2 shrink-0">
          {AGENT_TABS.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={`px-5 py-2.5 text-xs font-mono font-semibold transition-colors ${tab === t.id ? "border-b-2" : "text-ink-3 hover:text-ink-1"}`}
              style={tab === t.id ? { borderBottomColor: COLOR, color: COLOR } : {}}>
              {t.label}
            </button>
          ))}
        </div>

        {/* Content */}
        {tab === "build" ? (
          <AgentBuildTab
            name={name} setName={setName}
            desc={desc} setDesc={setDesc}
            mods={mods} toggleMod={toggleMod}
            extras={extras} setExtra={setExtra}
            generatedConfig={generatedConfig}
            fileName={fileName}
            serverOrigin={serverOrigin}
          />
        ) : (
          <div className="flex-1 overflow-y-auto p-5">
            <AgentPreviewTab
              name={name} desc={desc} mods={mods} extras={extras}
              fileName={fileName} generatedConfig={generatedConfig}
              serverOrigin={serverOrigin}
            />
          </div>
        )}
      </div>
    </div>
  );
}

// ─── AGENT BUILD TAB ─────────────────────────────────────────────────────────
function AgentBuildTab({ name, setName, desc, setDesc, mods, toggleMod, extras, setExtra, generatedConfig, fileName, serverOrigin }) {
  const [confirmed, setConfirmed] = useState(false);
  const curlDeploy = `curl -X POST ${serverOrigin}/api/agents/config \\\n  -H "Content-Type: application/toml" \\\n  --data-binary @${fileName}`;
  const wgetDeploy = `wget -qO- --post-file=${fileName} \\\n  --header="Content-Type: application/toml" \\\n  ${serverOrigin}/api/agents/config`;

  return (
    <div className="flex flex-1 overflow-hidden" style={{ minHeight: 0 }}>
      {/* Left — config form */}
      <div className="w-[42%] shrink-0 border-r border-border overflow-y-auto p-5 space-y-4">
        <div className="text-3xs font-mono uppercase tracking-wider flex items-center gap-2" style={{ color: COLOR }}>
          <span>●</span> {ENDPOINT_AGENT.label}
        </div>

        {/* Install script — above Why section */}
        <div className="bg-bg-0 border border-border rounded-md p-3">
          <div className="flex items-center justify-between mb-2">
            <div className="text-3xs text-ink-3 font-mono uppercase tracking-wider">Install Script</div>
            <button onClick={() => navigator.clipboard?.writeText(
              `# curl\ncurl -fsSL ${serverOrigin}/install/agent | sudo bash\n\n# wget\nwget -qO- ${serverOrigin}/install/agent | sudo bash`
            )} className="text-3xs text-brand font-mono hover:text-brand/80 flex items-center gap-1">
              <Copy size={10} /> Copy
            </button>
          </div>
          <pre className="text-3xs font-mono text-ink-1 whitespace-pre-wrap leading-relaxed">{`# curl\ncurl -fsSL ${serverOrigin}/install/agent | sudo bash\n\n# wget\nwget -qO- ${serverOrigin}/install/agent | sudo bash`}</pre>
        </div>

        {/* Why section */}
        <div className="bg-bg-2 border border-border rounded-md px-3 py-2">
          <div className="text-3xs text-ink-3 font-mono uppercase tracking-wider mb-1">Architecture</div>
          <div className="text-3xs text-ink-2 font-mono">{ENDPOINT_AGENT.why}</div>
        </div>

        <Field label="Agent Name">
          <input value={name} onChange={e => setName(e.target.value)} placeholder="my-endpoint-agent" className={inputCls} />
        </Field>
        <Field label="Description">
          <input value={desc} onChange={e => setDesc(e.target.value)} placeholder={ENDPOINT_AGENT.desc} className={inputCls} />
        </Field>

        {ENDPOINT_AGENT.fields.map(f => (
          <Field key={f.id} label={f.label}>
            <input value={extras[f.id] || ""} onChange={e => setExtra(f.id, e.target.value)}
              placeholder={f.placeholder} className={inputCls} />
          </Field>
        ))}

        <div>
          <label className="block text-3xs uppercase tracking-wider text-ink-3 font-mono mb-2">Modules</label>
          <div className="space-y-1.5">
            {mods.map(m => (
              <button key={m.id} onClick={() => toggleMod(m.id)}
                className="w-full flex items-center gap-2.5 px-3 py-2 rounded-md border text-xs font-mono text-left transition-colors"
                style={m.on ? { background: COLOR + "15", borderColor: COLOR + "60", color: "#f1f5f9" } : { borderColor: "#334155", color: "#64748b" }}>
                <span className="w-3.5 h-3.5 rounded-sm border flex items-center justify-center text-[9px] shrink-0"
                      style={m.on ? { background: COLOR, borderColor: COLOR } : { borderColor: "#4b5563" }}>
                  {m.on && "✓"}
                </span>
                {m.label}
              </button>
            ))}
          </div>
        </div>

        {/* Generated config — scroll to bottom to see */}
        <div className="border-t border-border pt-4 mt-2">
          <div className="flex items-center justify-between mb-2">
            <div className="text-3xs font-mono uppercase tracking-wider" style={{ color: COLOR }}>Generated Config — {fileName}</div>
            <button onClick={() => navigator.clipboard?.writeText(generatedConfig)} className="btn btn-outline">
              <Copy size={11} /> Copy
            </button>
          </div>
          <pre className="bg-bg-0 border border-border rounded-md p-3 text-3xs text-ink-1 font-mono whitespace-pre-wrap overflow-auto max-h-72">
            {generatedConfig}
          </pre>

          {/* Confirm & Deploy section */}
          <div className="mt-3 bg-bg-0 border rounded-md p-3" style={{ borderColor: confirmed ? COLOR + "60" : "#334155" }}>
            <div className="flex items-center justify-between mb-2">
              <div className="text-3xs font-mono uppercase tracking-wider text-ink-3">Confirm & Deploy</div>
              <button
                onClick={() => setConfirmed(c => !c)}
                className="text-3xs font-mono px-2 py-1 rounded border transition-colors"
                style={confirmed
                  ? { background: COLOR + "20", borderColor: COLOR + "60", color: COLOR }
                  : { borderColor: "#334155", color: "#64748b" }}>
                {confirmed ? "✓ Confirmed" : "Confirm Config"}
              </button>
            </div>
            {confirmed && (
              <div className="space-y-2 mt-2">
                <div className="text-3xs text-ink-3 font-mono mb-1">Deploy using curl or wget:</div>
                <div className="relative">
                  <pre className="bg-bg-2 border border-border rounded p-2 text-3xs text-ink-1 font-mono whitespace-pre-wrap">{curlDeploy}</pre>
                  <button onClick={() => navigator.clipboard?.writeText(curlDeploy.replace(/\\\n\s+/g, " "))}
                    className="absolute top-1.5 right-1.5 text-3xs text-ink-3 hover:text-ink-0 font-mono flex items-center gap-1">
                    <Copy size={9} /> curl
                  </button>
                </div>
                <div className="relative">
                  <pre className="bg-bg-2 border border-border rounded p-2 text-3xs text-ink-1 font-mono whitespace-pre-wrap">{wgetDeploy}</pre>
                  <button onClick={() => navigator.clipboard?.writeText(wgetDeploy.replace(/\\\n\s+/g, " "))}
                    className="absolute top-1.5 right-1.5 text-3xs text-ink-3 hover:text-ink-0 font-mono flex items-center gap-1">
                    <Copy size={9} /> wget
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Right — AI assist */}
      <div className="flex-1 flex flex-col p-5 overflow-hidden" style={{ minHeight: 0 }}>
        <div className="text-3xs font-mono uppercase tracking-wider mb-3 flex items-center gap-2">
          <span style={{ color: COLOR }}>●</span>
          <span className="text-ink-3">AI Assist — OpenCode Zen</span>
        </div>
        <AgentAIAssist name={name} mods={mods} extras={extras} />
      </div>
    </div>
  );
}

// ─── AGENT AI ASSIST ──────────────────────────────────────────────────────────
const AGENT_AI_SYSTEM = `You are a senior security platform engineer specializing in EDR/XDR endpoint agents.
You help configure, deploy, and optimize the OPXDR Endpoint Agent.
Topics: process monitoring, file integrity, registry monitoring, ETW/eBPF collection, memory scanning, local detections, secure communications, TLS hardening, performance tuning.
Give concise, accurate advice. When writing config or code, produce complete production-ready examples.`;

function AgentAIAssist({ name, mods, extras }) {
  const [messages, setMessages]   = useState([]);
  const [input, setInput]         = useState("");
  const [streaming, setStreaming] = useState(false);
  const bottomRef = useRef(null);
  const inputRef  = useRef(null);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages]);

  const enabledMods = mods.filter(m => m.on).map(m => m.label).join(", ");
  const agentCtx = `Agent name: "${name || "unnamed"}". Enabled modules: ${enabledMods || "none"}. Gateway: ${extras.gatewayUrl || "not set"}.`;

  async function send(text) {
    if (!text.trim() || streaming) return;
    const userMsg = { role: "user", content: text };
    const history = [...messages, userMsg];
    setMessages([...history, { role: "assistant", content: "..." }]);
    setInput(""); setStreaming(true);
    try {
      await callAgent("ruleAssistant", history,
        chunk => setMessages([...history, { role: "assistant", content: chunk }]),
        { system: `${AGENT_AI_SYSTEM}\n\n${agentCtx}` }
      );
    } catch (e) {
      setMessages([...history, { role: "assistant", content: `[Error: ${e.message}]` }]);
    }
    setStreaming(false);
    inputRef.current?.focus();
  }

  const quickPrompts = [
    "How do I harden TLS for secure communications?",
    "Best practices for ETW collection on Windows?",
    "How to minimize CPU impact during file integrity monitoring?",
    "How should I tune memory scanning for a production server?",
    "Write a systemd service file to run this agent on Linux",
    "What are the recommended heartbeat and retry settings?",
  ];

  return (
    <div className="flex flex-col h-full" style={{ minHeight: 0 }}>
      {messages.length === 0 && (
        <div className="mb-4 shrink-0">
          <div className="text-3xs text-ink-3 font-mono uppercase tracking-wider mb-2">Quick prompts</div>
          <div className="flex flex-wrap gap-2">
            {quickPrompts.map((p, i) => (
              <button key={i} onClick={() => send(p)}
                className="text-3xs bg-bg-2 border border-border text-ink-2 px-2.5 py-1.5 rounded font-mono transition-colors text-left"
                onMouseEnter={e => e.currentTarget.style.borderColor = COLOR}
                onMouseLeave={e => e.currentTarget.style.borderColor = ""}>
                {p}
              </button>
            ))}
          </div>
        </div>
      )}
      <div className="flex-1 overflow-y-auto space-y-3 mb-3" style={{ minHeight: 0 }}>
        {messages.map((m, i) => (
          <div key={i} className={`flex gap-2.5 ${m.role === "user" ? "justify-end" : "justify-start"}`}>
            {m.role === "assistant" && (
              <div className="w-6 h-6 rounded-full flex items-center justify-center text-xs shrink-0 mt-0.5 border"
                   style={{ background: COLOR + "20", borderColor: COLOR + "40" }}>🤖</div>
            )}
            <div className="max-w-[80%] rounded-lg px-3 py-2 text-xs font-mono whitespace-pre-wrap bg-bg-2 border border-border text-ink-1"
                 style={m.role === "user" ? { borderColor: COLOR + "40" } : {}}>
              {m.content}
              {m.role === "assistant" && streaming && i === messages.length - 1 && (
                <span className="inline-block w-1.5 h-3 ml-1 animate-pulse" style={{ background: COLOR }} />
              )}
            </div>
            {m.role === "user" && (
              <div className="w-6 h-6 rounded-full bg-ok/20 border border-ok/40 flex items-center justify-center text-xs shrink-0 mt-0.5">👤</div>
            )}
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
      <div className="flex gap-2 items-end shrink-0">
        <textarea ref={inputRef} value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(input); } }}
          placeholder="Ask about configuration, deployment, performance tuning, or security hardening..."
          disabled={streaming} rows={2}
          className="flex-1 bg-bg-0 border border-border rounded-md px-3 py-2 text-xs font-mono text-ink-0 focus:border-brand outline-none resize-none disabled:opacity-50"
        />
        <button onClick={() => send(input)} disabled={!input.trim() || streaming}
          className="btn disabled:opacity-40 shrink-0"
          style={{ background: COLOR + "20", border: `1px solid ${COLOR}60`, color: COLOR }}>
          <Send size={13} />
        </button>
      </div>
      <div className="text-3xs text-ink-3 font-mono mt-1.5 shrink-0">
        OpenCode Zen (OCZ_API_KEY) · Shift+Enter for newline
      </div>
    </div>
  );
}

// ─── AGENT PREVIEW TAB ────────────────────────────────────────────────────────
function AgentPreviewTab({ name, desc, mods, extras, fileName, generatedConfig, serverOrigin }) {
  const enabledMods  = mods.filter(m => m.on);
  const disabledMods = mods.filter(m => !m.on);

  return (
    <div className="space-y-4">
      <div className="panel p-4 border-l-4" style={{ borderLeftColor: COLOR }}>
        <div className="flex items-start justify-between mb-3">
          <div className="flex items-center gap-3">
            <span className="text-2xl">🖥️</span>
            <div>
              <div className="text-sm font-extrabold text-ink-0">{name || "opxdr-endpoint"}</div>
              <div className="text-3xs text-ink-3 font-mono mt-0.5">{desc || ENDPOINT_AGENT.desc}</div>
            </div>
          </div>
          <span className="text-3xs text-ink-3 font-mono">{fileName}</span>
        </div>

        <div className="bg-bg-2 border border-border rounded px-3 py-2 mb-3">
          <div className="text-3xs text-ink-3 font-mono uppercase tracking-wider mb-1">Architecture</div>
          <div className="text-3xs text-ink-2 font-mono">{ENDPOINT_AGENT.why}</div>
        </div>

        <div className="grid grid-cols-2 gap-3 mb-3">
          <div>
            <div className="text-3xs text-ink-3 font-mono uppercase tracking-wider mb-1.5">Enabled</div>
            {enabledMods.map(m => (
              <div key={m.id} className="flex items-center gap-1.5 text-3xs font-mono mb-1" style={{ color: COLOR }}>
                <span>✓</span> {m.label}
              </div>
            ))}
          </div>
          <div>
            <div className="text-3xs text-ink-3 font-mono uppercase tracking-wider mb-1.5">Disabled</div>
            {disabledMods.map(m => (
              <div key={m.id} className="flex items-center gap-1.5 text-3xs font-mono text-ink-3 mb-1">
                <span>○</span> {m.label}
              </div>
            ))}
          </div>
        </div>

        {Object.entries(extras).filter(([, v]) => v).length > 0 && (
          <div className="grid grid-cols-2 gap-2 text-3xs font-mono border-t border-border pt-3">
            {Object.entries(extras).filter(([, v]) => v).map(([k, v]) => (
              <div key={k}><span className="text-ink-3">{k}:</span> <span className="text-ink-1">{v}</span></div>
            ))}
          </div>
        )}
      </div>

      {/* Install command card */}
      <div className="panel p-4">
        <div className="text-3xs text-ink-3 font-mono uppercase tracking-wider mb-3">Install Commands</div>
        <div className="space-y-2">
          {[
            { label: "curl", cmd: `curl -fsSL ${serverOrigin}/install/agent | sudo bash` },
            { label: "wget", cmd: `wget -qO- ${serverOrigin}/install/agent | sudo bash` },
          ].map(({ label, cmd }) => (
            <div key={label} className="relative bg-bg-0 border border-border rounded p-2">
              <pre className="text-3xs font-mono text-ink-1 pr-12">{cmd}</pre>
              <button onClick={() => navigator.clipboard?.writeText(cmd)}
                className="absolute top-1.5 right-1.5 text-3xs text-ink-3 hover:text-ink-0 flex items-center gap-1 font-mono">
                <Copy size={9} /> {label}
              </button>
            </div>
          ))}
        </div>
      </div>

      <details className="panel">
        <summary className="px-4 py-3 text-3xs text-ink-3 font-mono cursor-pointer hover:text-ink-1 flex items-center gap-2">
          <span style={{ color: COLOR }}>▶</span> View {fileName}
        </summary>
        <pre className="px-4 pb-4 text-3xs text-ink-1 font-mono overflow-auto max-h-72 whitespace-pre-wrap border-t border-border pt-3">
          {generatedConfig}
        </pre>
      </details>
    </div>
  );
}
