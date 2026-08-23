// OPXDR — backend
// Provides:
//   GET  /api/health
//   GET  /api/rules               — local files merged with Wazuh API rules
//   GET  /api/rules/:id           — single rule detail (with raw XML/YAML)
//   GET  /api/playbooks           — IR playbooks discovered on disk
//   GET  /api/alerts/recent       — last N alerts (Wazuh Indexer → file fallback + injected)
//   GET  /api/alerts/stream       — SSE feed (Wazuh Indexer polling → tail fallback + injected)
//   POST /api/alerts/inject       — push a custom-formatted alert into the live feed
//   POST /api/claude              — proxy to OpenCode/Anthropic for AI replies
//
// Reads creds from .env (see .env.example).
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import https from "node:https";
import crypto from "node:crypto";
import dgram from "node:dgram";
import net from "node:net";
import { spawn, execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { EventEmitter } from "node:events";
import os from "node:os";
import geoip from "geoip-lite";
dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVER_DATA_DIR = path.join(__dirname, "data");
const SIEM_AGENT_TELEMETRY_LOG = path.join(SERVER_DATA_DIR, "siem-agent-telemetry.jsonl");
const OPXDR_SIEM_AGENT_VERSION = "opxdr-siem-agent/1.1.1";
const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

const PORT = parseInt(process.env.PORT || "8787", 10);
const WAZUH_API_URL = process.env.WAZUH_API_URL || "https://localhost:55000";
const WAZUH_API_USER = process.env.WAZUH_API_USER || "wazuh-wui";
const WAZUH_API_PASS = process.env.WAZUH_API_PASS || "";
const WAZUH_API_INSECURE = (process.env.WAZUH_API_INSECURE || "true") === "true";
const RULES_LOCAL_ROOT = process.env.RULES_LOCAL_ROOT || "/home/soc-admin/SecurityOperations/github-staging";
const CUSTOM_RULES_DIR = process.env.CUSTOM_RULES_DIR || "/home/soc-admin/SecurityOperations/custom_rules";
const CUSTOM_PLAYBOOKS_DIR = process.env.CUSTOM_PLAYBOOKS_DIR || "/home/soc-admin/SecurityOperations/custom_playbooks";
const WAZUH_RULES_DIR = process.env.WAZUH_RULES_DIR || "/var/ossec/etc/rules";
const WAZUH_AUTO_RESTART = (process.env.WAZUH_AUTO_RESTART || "true") === "true";
const WAZUH_ALERTS_LOG = process.env.WAZUH_ALERTS_LOG || "/var/ossec/logs/alerts/alerts.json";

// Optional SIEM fanout. OPXDR remains the source-of-truth event broker; each
// destination only activates when its endpoint/token env vars are configured.
const SIEM_FORWARD_ENABLED = (process.env.SIEM_FORWARD_ENABLED || "true") === "true";
const SIEM_SYSLOG_HOST = process.env.SIEM_SYSLOG_HOST || "";
const SIEM_SYSLOG_PORT = parseInt(process.env.SIEM_SYSLOG_PORT || "514", 10);
const SIEM_SYSLOG_PROTO = (process.env.SIEM_SYSLOG_PROTO || "udp").toLowerCase();
const SIEM_SYSLOG_FORMAT = (process.env.SIEM_SYSLOG_FORMAT || "cef").toLowerCase();
const SPLUNK_HEC_URL = process.env.SPLUNK_HEC_URL || "";
const SPLUNK_HEC_TOKEN = process.env.SPLUNK_HEC_TOKEN || "";
const SPLUNK_HEC_INDEX = process.env.SPLUNK_HEC_INDEX || "opxdr";
const ELASTIC_INGEST_URL = process.env.ELASTIC_INGEST_URL || "";
const ELASTIC_API_KEY = process.env.ELASTIC_API_KEY || "";
const ELASTIC_USERNAME = process.env.ELASTIC_USERNAME || "";
const ELASTIC_PASSWORD = process.env.ELASTIC_PASSWORD || "";
const SENTINEL_WORKSPACE_ID = process.env.SENTINEL_WORKSPACE_ID || "";
const SENTINEL_SHARED_KEY = process.env.SENTINEL_SHARED_KEY || "";
const SENTINEL_LOG_TYPE = process.env.SENTINEL_LOG_TYPE || "OPXDRTestfire";
const QRADAR_INGEST_URL = process.env.QRADAR_INGEST_URL || "";
const QRADAR_TOKEN = process.env.QRADAR_TOKEN || "";
const CHRONICLE_INGEST_URL = process.env.CHRONICLE_INGEST_URL || "";
const CHRONICLE_TOKEN = process.env.CHRONICLE_TOKEN || "";

// Slack + AI auto-report config
const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL || "";
const SLACK_CHANNEL = process.env.SLACK_CHANNEL || "#soc-alerts";
const SLACK_USERNAME = process.env.SLACK_USERNAME || "OPXDR";
const AI_AUTO_REPORT = (process.env.AI_AUTO_REPORT || "false") === "true";
const AI_AUTO_REPORT_MIN_LEVEL = parseInt(process.env.AI_AUTO_REPORT_MIN_LEVEL || "12", 10);
const AI_AUTO_SLACK_NOTIFY = (process.env.AI_AUTO_SLACK_NOTIFY || "true") === "true";

// Make sure custom dirs exist
for (const d of [CUSTOM_RULES_DIR, CUSTOM_PLAYBOOKS_DIR]) {
  try { fs.mkdirSync(d, { recursive: true }); } catch {}
}
try { fs.mkdirSync(SERVER_DATA_DIR, { recursive: true }); } catch {}

const insecureAgent = new https.Agent({ rejectUnauthorized: !WAZUH_API_INSECURE });

// ─── Wazuh API helpers ────────────────────────────────────────────────────
let wazuhToken = null;
let wazuhTokenExp = 0;

async function wazuhAuth() {
  if (wazuhToken && Date.now() < wazuhTokenExp) return wazuhToken;
  if (!WAZUH_API_PASS) throw new Error("WAZUH_API_PASS not configured in .env");
  const auth = Buffer.from(`${WAZUH_API_USER}:${WAZUH_API_PASS}`).toString("base64");
  const res = await fetch(`${WAZUH_API_URL}/security/user/authenticate`, {
    method: "POST",
    headers: { Authorization: `Basic ${auth}` },
    agent: insecureAgent,
  });
  if (!res.ok) throw new Error(`Wazuh auth failed: ${res.status} ${await res.text()}`);
  const j = await res.json();
  wazuhToken = j?.data?.token;
  // tokens default to 900s — refresh after 800s
  wazuhTokenExp = Date.now() + 800_000;
  return wazuhToken;
}

async function wazuh(pathName, paramsOrOpts = {}) {
  const token = await wazuhAuth();
  let opts = { method: "GET", headers: { Authorization: `Bearer ${token}` }, agent: insecureAgent };
  let params = paramsOrOpts;
  if (paramsOrOpts.method || paramsOrOpts.body) {
    opts = { ...opts, ...paramsOrOpts };
    params = {};
  }
  const url = new URL(`${WAZUH_API_URL}${pathName}`);
  for (const [k, v] of Object.entries(params)) if (v != null) url.searchParams.set(k, String(v));
  const res = await fetch(url, opts);
  if (!res.ok) throw new Error(`Wazuh ${pathName} -> ${res.status}: ${await res.text()}`);
  return res.json();
}

// node-fetch v3 / native fetch in node 18 doesn't accept the `agent` option directly;
// Provide a shim using node:https for the self-signed case.
import nodeFetch from "node-fetch";
globalThis.fetch = nodeFetch;

// ─── Local rule discovery ─────────────────────────────────────────────────
async function walk(dir) {
  const out = [];
  let entries;
  try { entries = await fsp.readdir(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...(await walk(p)));
    else out.push(p);
  }
  return out;
}

const sevFromLevel = (l) => {
  const n = parseInt(l, 10);
  if (n >= 15) return "CRITICAL";
  if (n >= 12) return "HIGH";
  if (n >= 7) return "MEDIUM";
  return "LOW";
};

function deriveTactic(t) {
  const s = (t || "").toLowerCase();
  if (/initial.access|phish|exploit/.test(s)) return "Initial Access";
  if (/execut|command|script|shell/.test(s)) return "Execution";
  if (/escalat|privilege|sudo|admin/.test(s)) return "Privilege Escalation";
  if (/lateral|rdp|smb|wmi|pass.hash/.test(s)) return "Lateral Movement";
  if (/credential|password|spray|brute/.test(s)) return "Credential Access";
  if (/discover|scan|enum/.test(s)) return "Discovery";
  if (/c2|beacon|command.control/.test(s)) return "Command & Control";
  if (/exfil|stage|upload|transfer/.test(s)) return "Exfiltration";
  if (/collect|mailbox|data/.test(s)) return "Collection";
  if (/persist|startup|service|registry/.test(s)) return "Persistence";
  if (/impact|ransom|ddos|wipe/.test(s)) return "Impact";
  if (/honeypot|cowrie|dionaea|heralding|mailoney/.test(s)) return "Initial Access";
  return "Defense Evasion";
}

function classifyGroup(filePath) {
  const p = filePath.toLowerCase();
  if (p.startsWith(CUSTOM_RULES_DIR.toLowerCase())) return { key: "custom", label: "Custom Rules (Authored)", color: "#22c55e", icon: "📝" };
  if (p.startsWith(WAZUH_RULES_DIR.toLowerCase())) return { key: "wazuh-fs", label: "Wazuh Rules (filesystem)", color: "#22d3ee", icon: "🛡️" };
  if (p.includes("/honeypot/")) return { key: "honeypot", label: "Honeypot Cluster", color: "#f97316", icon: "🍯" };
  if (p.includes("/aptpack")) return { key: "aptpack", label: "APTPACK Threat Packs", color: "#ef4444", icon: "☠️" };
  if (p.includes("/apt31")) return { key: "apt31", label: "APT31 (Zirconium)", color: "#a855f7", icon: "🐼" };
  if (p.includes("/ifrag") || p.includes("rdp")) return { key: "ifrag", label: "iFrag-DHV (RDP)", color: "#06b6d4", icon: "🖥️" };
  if (p.includes("/edge") || p.includes("vpn")) return { key: "edge", label: "Edge Appliance / VPN", color: "#38bdf8", icon: "🔀" };
  if (p.includes("malwaredetection") || p.endsWith(".yar")) return { key: "malware", label: "Malware (YARA)", color: "#fb7185", icon: "🦠" };
  if (p.includes("/botnets/")) return { key: "botnets", label: "Botnets", color: "#dc2626", icon: "🤖" };
  return { key: "other", label: "Other Detections", color: "#64748b", icon: "📂" };
}

// Parse a Wazuh XML rules file into one or more rule objects
function parseWazuhXml(xmlText, filePath) {
  const rules = [];
  const ruleRe = /<rule\s+id="(\d+)"[^>]*level="(\d+)"[^>]*>([\s\S]*?)<\/rule>/g;
  let m;
  while ((m = ruleRe.exec(xmlText)) !== null) {
    const [, ruleId, level, body] = m;
    const desc = (body.match(/<description>([\s\S]*?)<\/description>/)?.[1] || "").trim();
    const group = (body.match(/<group>([\s\S]*?)<\/group>/)?.[1] || "").trim();
    const mitre = [...body.matchAll(/<id>(T\d+(?:\.\d+)?)<\/id>/g)].map((x) => x[1]).join(",");
    const decoded = (body.match(/<decoded_as>([\s\S]*?)<\/decoded_as>/)?.[1] || "").trim();
    const fld = body.match(/<field\s+name="([^"]+)"[^>]*>([\s\S]*?)<\/field>/);
    const ioc = fld ? `${fld[1]}:${fld[2].trim()}` : "";
    const tactic = deriveTactic(group + " " + desc);
    rules.push({
      wazuhRuleId: ruleId,
      id: `LOC-${ruleId}`,
      file: path.basename(filePath),
      filePath,
      name: desc || `Rule ${ruleId}`,
      level: parseInt(level, 10),
      severity: sevFromLevel(level),
      group,
      mitre: mitre || "—",
      tactic,
      decoded,
      ioc,
      source: "local-xml",
    });
  }
  return rules;
}

// Sigma/YAML-style detection rules
function parseYamlRule(text, filePath) {
  const get = (re) => (text.match(re)?.[1] || "").trim().replace(/^['"]|['"]$/g, "");
  const title = get(/^\s*title:\s*(.+)$/m);
  const id = get(/^\s*id:\s*(.+)$/m) || path.basename(filePath, path.extname(filePath));
  const lvl = get(/^\s*level:\s*(.+)$/m).toLowerCase();
  const tags = [...text.matchAll(/-\s*attack\.([a-z0-9_]+)/g)].map((x) => x[1]);
  const techs = [...text.matchAll(/-\s*attack\.(t\d+(?:\.\d+)?)/gi)].map((x) => x[1].toUpperCase());
  const sev = lvl === "critical" ? "CRITICAL" : lvl === "high" ? "HIGH" : lvl === "medium" ? "MEDIUM" : "LOW";
  const tactic = deriveTactic(tags.join(" ") + " " + title);
  return [{
    id: `LOC-${id.slice(0, 12)}`,
    wazuhRuleId: null,
    file: path.basename(filePath),
    filePath,
    name: title || path.basename(filePath),
    level: null,
    severity: sev,
    mitre: techs.join(",") || "—",
    tactic,
    source: "local-yaml",
  }];
}

// YARA
function parseYara(text, filePath) {
  const rules = [];
  const re = /rule\s+(\w+)/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    rules.push({
      id: `LOC-${m[1].slice(0, 12)}`,
      wazuhRuleId: null,
      file: path.basename(filePath),
      filePath,
      name: m[1],
      level: null,
      severity: "HIGH",
      mitre: "—",
      tactic: "Execution",
      source: "local-yara",
    });
  }
  return rules;
}

async function loadLocalRules() {
  // Walk: staged rules repo + custom rules dir + wazuh rules filesystem dir
  const roots = [RULES_LOCAL_ROOT, CUSTOM_RULES_DIR, WAZUH_RULES_DIR];
  const all = [];
  for (const r of roots) all.push(...(await walk(r)));
  const out = [];
  for (const f of all) {
    try {
      const ext = path.extname(f).toLowerCase();
      if (ext === ".bak" || f.includes(".bak.")) continue;
      const txt = await fsp.readFile(f, "utf8");
      let parsed = [];
      if (ext === ".xml") parsed = parseWazuhXml(txt, f);
      else if (ext === ".yml" || ext === ".yaml") parsed = parseYamlRule(txt, f);
      else if (ext === ".yar" || ext === ".yara") parsed = parseYara(txt, f);
      for (const r of parsed) {
        const grp = classifyGroup(f);
        out.push({ ...r, group: grp.key, groupLabel: grp.label, groupColor: grp.color, groupIcon: grp.icon });
      }
    } catch {}
  }
  return out;
}

// ─── Wazuh live rules ─────────────────────────────────────────────────────
async function loadWazuhApiRules() {
  try {
    const j = await wazuh("/rules", { limit: 500, offset: 0, status: "enabled" });
    const items = j?.data?.affected_items || [];
    return items.map((r) => ({
      id: `WAZ-${r.id}`,
      wazuhRuleId: String(r.id),
      file: r.filename || "—",
      filePath: r.relative_dirname ? `${r.relative_dirname}/${r.filename}` : r.filename,
      name: r.description || `Rule ${r.id}`,
      level: r.level,
      severity: sevFromLevel(r.level),
      mitre: (r.mitre?.id || []).join(",") || "—",
      tactic: deriveTactic((r.groups || []).join(" ") + " " + (r.description || "")),
      group: "wazuh-live",
      groupLabel: "Wazuh API (Live, enabled)",
      groupColor: "#22d3ee",
      groupIcon: "📡",
      source: "wazuh-api",
      groups: r.groups || [],
    }));
  } catch (e) {
    console.warn("[wazuh] could not load live rules:", e.message);
    return [];
  }
}

// ─── Routes ───────────────────────────────────────────────────────────────
app.get("/api/health", async (_req, res) => {
  let wazuh = "down";
  let indexer = WAZUH_INDEXER_PASS ? "down" : "not configured";
  try { await wazuhAuth(); wazuh = "ok"; } catch (e) { wazuh = e.message; }
  if (WAZUH_INDEXER_PASS) {
    try {
      await queryIndexer({ minLevel: ALERT_MIN_LEVEL, size: 1 });
      indexer = "ok";
    } catch (e) { indexer = e.message.slice(0, 100); }
  }
  res.json({
    ok: true,
    wazuh,
    wazuh_url: WAZUH_API_URL,
    indexer,
    indexer_url: WAZUH_INDEXER_URL,
    indexer_index: WAZUH_INDEXER_INDEX,
    alert_source: WAZUH_INDEXER_PASS ? "indexer" : "file",
    rules_root: RULES_LOCAL_ROOT,
    alerts_log: WAZUH_ALERTS_LOG,
    ai_provider: process.env.OPENCODE_API_KEY ? "opencode" : process.env.ANTHROPIC_API_KEY ? "anthropic" : "none",
    slack_enabled: !!SLACK_WEBHOOK_URL,
    ai_auto_report: AI_AUTO_REPORT,
    ai_auto_report_min_level: AI_AUTO_REPORT_MIN_LEVEL,
  });
});

// ─── Wazuh Agents ───────────────────────────────────────────────────────
async function readLatestSiemTelemetryByAgent() {
  const byAgent = {};
  try {
    const raw = await new Promise((resolve, reject) => {
      const proc = spawn("tail", ["-n", "400", SIEM_AGENT_TELEMETRY_LOG]);
      let buf = "";
      proc.stdout.on("data", d => buf += d.toString());
      proc.on("close", () => resolve(buf));
      proc.on("error", reject);
    });
    for (const line of raw.split("\n")) {
      if (!line.trim()) continue;
      try {
        const event = JSON.parse(line);
        const id = String(event.agent_id || event.agentId || "");
        if (!id) continue;
        const seen = Date.parse(event.receivedAt || event.time || "");
        const prev = byAgent[id];
        if (!prev || seen > Date.parse(prev.receivedAt || prev.time || "")) byAgent[id] = event;
      } catch {}
    }
  } catch {}
  return byAgent;
}

app.get("/api/agents", async (req, res) => {
  try {
    let wazuhError = null;
    const j = await wazuh("/agents", { limit: parseInt(req.query.limit || "500", 10), offset: 0 }).catch(e => {
      wazuhError = e;
      return { data: { affected_items: [] } };
    });
    const items = j?.data?.affected_items || [];
    const summary = await wazuh("/agents/summary/status").catch(() => ({}));
    const latestSiem = await readLatestSiemTelemetryByAgent();
    const seenAgentIds = new Set(items.map(a => String(a.id)));
    const agents = items.map(a => {
      const opxdr = latestSiem[String(a.id)];
      return {
        id: a.id,
        name: a.name,
        ip: a.ip,
        status: a.status,
        os: { name: a.os?.name, version: a.os?.version, platform: a.os?.platform },
        version: a.version,
        opxdrAgent: opxdr ? {
          installed: true,
          version: opxdr.agent_version || OPXDR_SIEM_AGENT_VERSION,
          lastSeen: opxdr.receivedAt || opxdr.time,
          hostname: opxdr.hostname,
          ip: opxdr.ip,
          telemetrySchema: opxdr.telemetry_schema || "opxdr.siem.telemetry.v1",
          activePorts: Array.isArray(opxdr.network) ? opxdr.network.length : 0,
          authEvents: Array.isArray(opxdr.auth) ? opxdr.auth.length : 0,
          processCount: Array.isArray(opxdr.processes) ? opxdr.processes.length : 0,
        } : { installed: false, version: OPXDR_SIEM_AGENT_VERSION },
        group: a.group,
        node: a.node,
        lastKeepAlive: a.lastKeepAlive,
        dateAdd: a.dateAdd,
        honeypotLocation: agentHoneypotLocation(a),
        honeypotStatus: honeypotRuntimeStatus(a),
        honeypotServices: Object.values(HONEYPOT_SERVICE_CATALOG),
      };
    });
    for (const [id, opxdr] of Object.entries(latestSiem)) {
      if (seenAgentIds.has(String(id))) continue;
      agents.push({
        id,
        name: opxdr.agent_name || opxdr.hostname || `OPXDR ${id}`,
        ip: opxdr.ip || "external",
        status: "active",
        os: { name: opxdr.system?.os || "OPXDR telemetry", version: opxdr.system?.kernel || "", platform: opxdr.system?.arch || "" },
        version: "external",
        opxdrAgent: {
          installed: true,
          version: opxdr.agent_version || OPXDR_SIEM_AGENT_VERSION,
          lastSeen: opxdr.receivedAt || opxdr.time,
          hostname: opxdr.hostname,
          ip: opxdr.ip,
          telemetrySchema: opxdr.telemetry_schema || "opxdr.siem.telemetry.v1",
          activePorts: Array.isArray(opxdr.network) ? opxdr.network.length : 0,
          authEvents: Array.isArray(opxdr.auth) ? opxdr.auth.length : 0,
          processCount: Array.isArray(opxdr.processes) ? opxdr.processes.length : 0,
        },
        group: "opxdr-external",
        node: "opxdr",
        lastKeepAlive: opxdr.receivedAt || opxdr.time,
        dateAdd: opxdr.receivedAt || opxdr.time,
        honeypotLocation: agentHoneypotLocation({ name: opxdr.agent_name || opxdr.hostname, ip: opxdr.ip }),
        honeypotStatus: { installed: false, running: false, enabled: false, source: "not-installed", services: [] },
        honeypotServices: Object.values(HONEYPOT_SERVICE_CATALOG),
      });
    }
    res.json({
      agents,
      status_summary: summary?.data?.affected_items || {},
      total: items.length,
      warning: wazuhError ? `Wazuh unavailable; showing OPXDR telemetry agents only: ${wazuhError.message}` : null,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});


function localHoneypotControl(enabled) {
  const action = enabled ? "start" : "stop";
  commandOutput("sudo", ["-n", "systemctl", action, "opxdr-honeypot"]);
  const active = commandOutput("sudo", ["-n", "systemctl", "is-active", "opxdr-honeypot"]).trim();
  return active === "active";
}

app.post("/api/honeypot/agents/:id/state", async (req, res) => {
  try {
    const agentId = String(req.params.id || "");
    const enabled = !!req.body?.enabled;
    const j = await wazuh("/agents", { limit: 500, offset: 0 }).catch(() => ({}));
    const found = (j?.data?.affected_items || []).find(a => String(a.id) === agentId) || { id: agentId, name: os.hostname(), ip: "127.0.0.1" };
    if (!isLocalAgent(found)) {
      return res.status(409).json({ error: "remote honeypot control requires running the install script on that endpoint", agentId, status: honeypotRuntimeStatus(found) });
    }
    localHoneypotControl(enabled);
    res.json({ ok: true, agentId, status: honeypotRuntimeStatus(found) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put("/api/agents/:id/restart", async (req, res) => {
  try {
    const token = await wazuhAuth();
    const r = await fetch(`${WAZUH_API_URL}/agents/${req.params.id}/restart`, {
      method: "PUT", headers: { Authorization: `Bearer ${token}` }, agent: insecureAgent,
    });
    if (!r.ok) throw new Error(`Wazuh restart -> ${r.status}: ${await r.text()}`);
    const j = await r.json();
    res.json({ ok: true, data: j?.data });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete("/api/agents/:id", async (req, res) => {
  try {
    const token = await wazuhAuth();
    const url = new URL(`${WAZUH_API_URL}/agents`);
    url.searchParams.set("agents_list", req.params.id);
    const r = await fetch(url, { method: "DELETE", headers: { Authorization: `Bearer ${token}` }, agent: insecureAgent });
    if (!r.ok) throw new Error(`Wazuh DELETE agents -> ${r.status}: ${await r.text()}`);
    const j = await r.json();
    res.json({ ok: true, data: j?.data });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});



const GEO_BY_CC_SERVER = {
  US: { lat: 38.9, lng: -77.0, name: "United States" },
  CN: { lat: 35.9, lng: 104.2, name: "China" },
  RU: { lat: 55.7, lng: 37.6, name: "Russia" },
  DE: { lat: 52.5, lng: 13.4, name: "Germany" },
  NL: { lat: 52.4, lng: 4.9, name: "Netherlands" },
  SG: { lat: 1.35, lng: 103.8, name: "Singapore" },
  IN: { lat: 20.6, lng: 78.9, name: "India" },
  BR: { lat: -14.2, lng: -51.9, name: "Brazil" },
  GB: { lat: 51.5, lng: -0.1, name: "UK" },
  UA: { lat: 49.0, lng: 32.0, name: "Ukraine" },
  IR: { lat: 32.4, lng: 53.7, name: "Iran" },
  JP: { lat: 36.2, lng: 138.3, name: "Japan" },
  KP: { lat: 40.3, lng: 127.5, name: "North Korea" },
  FR: { lat: 46.2, lng: 2.2, name: "France" },
  CA: { lat: 56.1, lng: -106.3, name: "Canada" },
};

function ipToCyberGeo(ip = "") {
  const cleanIp = String(ip || "").trim();
  if (isPrivateOrLocalIp(cleanIp)) {
    const local = systemHoneypotGeo();
    return { ...local, name: "Private network", ip: cleanIp || "-", geoSource: "private" };
  }

  const hit = geoip.lookup(cleanIp);
  if (hit?.ll?.length === 2 && Number.isFinite(hit.ll[0]) && Number.isFinite(hit.ll[1])) {
    const cc = String(hit.country || "").toUpperCase() || "--";
    const name = [hit.city, hit.region, cc].filter(Boolean).join(", ") || (GEO_BY_CC_SERVER[cc]?.name || cc);
    return {
      lat: hit.ll[0],
      lng: hit.ll[1],
      name,
      city: hit.city || "",
      region: hit.region || "",
      cc,
      ip: cleanIp || "-",
      geoSource: "geoip-lite",
    };
  }

  const first = parseInt(cleanIp.split(".")[0] || "0", 10);
  let cc = "BR";
  if (first >= 1 && first <= 50) cc = "CN";
  else if (first >= 51 && first <= 79) cc = "US";
  else if (first >= 80 && first <= 90) cc = "DE";
  else if (first >= 91 && first <= 100) cc = "US";
  else if (first >= 101 && first <= 130) cc = "DE";
  else if (first >= 131 && first <= 180) cc = "RU";
  else if (first >= 181 && first <= 220) cc = "IN";
  const geo = GEO_BY_CC_SERVER[cc] || GEO_BY_CC_SERVER.BR;
  return { ...geo, cc, ip: cleanIp || "-", geoSource: "fallback" };
}

function parseKvLog(line = "") {
  const out = {};
  const re = /([a-zA-Z0-9_.-]+)=([^\s]+)/g;
  let m;
  while ((m = re.exec(String(line))) !== null) out[m[1]] = m[2];
  return out;
}

function honeypotMetaForService(service = "") {
  const s = String(service).toLowerCase();
  if (s === "ssh") return { type: "honeypot", severity: "high", cve: "CVE-2022-1388", malware: "Credential Probe", actor: "Unknown", tactic: "Credential Access", mitre: "T1110,T1021.004" };
  if (s === "http") return { type: "honeypot", severity: "critical", cve: "CVE-2022-1388", malware: "Zmap", actor: "Unknown", tactic: "Initial Access", mitre: "T1190,T1595.002" };
  if (s === "ftp") return { type: "honeypot", severity: "high", cve: "CVE-2022-1388", malware: "Credential Probe", actor: "Unknown", tactic: "Credential Access", mitre: "T1110,T1021.002" };
  if (s === "smb") return { type: "honeypot", severity: "high", cve: "CVE-2020-0796", malware: "Share Scanner", actor: "Unknown", tactic: "Lateral Movement", mitre: "T1021.002,T1135" };
  if (s === "smtp") return { type: "honeypot", severity: "medium", cve: "CVE-2023-23397", malware: "Relay Probe", actor: "Unknown", tactic: "Phishing", mitre: "T1598,T1110" };
  return { type: "honeypot", severity: "medium", cve: "CVE-2022-1388", malware: "Scanner", actor: "Unknown", tactic: "Reconnaissance", mitre: "T1595" };
}

function servicePort(service, fallback = "") {
  const spec = HONEYPOT_SERVICE_CATALOG[String(service).toLowerCase()];
  return parseInt(fallback || spec?.port || "0", 10) || spec?.port || 0;
}

function commandOutput(cmd, args = []) {
  try { return execFileSync(cmd, args, { encoding: "utf8", timeout: 2500, stdio: ["ignore", "pipe", "ignore"] }); }
  catch { return ""; }
}

function isLocalAgent(agent = {}) {
  const id = String(agent.id || "");
  const name = String(agent.name || "").toLowerCase();
  const ip = String(agent.ip || "").toLowerCase();
  const host = os.hostname().toLowerCase();
  return id === "000" || name === host || ip === "127.0.0.1" || ip === "localhost" || ip === "::1";
}

function honeypotRuntimeStatus(agent = {}) {
  if (!isLocalAgent(agent)) {
    return { installed: false, running: false, enabled: false, source: "not-installed", services: [] };
  }
  const serviceFile = "/etc/systemd/system/opxdr-honeypot.service";
  const active = commandOutput("systemctl", ["is-active", "opxdr-honeypot"]).trim();
  const enabled = commandOutput("systemctl", ["is-enabled", "opxdr-honeypot"]).trim();
  const sockets = commandOutput("ss", ["-ltn"]);
  const services = Object.values(HONEYPOT_SERVICE_CATALOG).map(spec => ({
    ...spec,
    listening: new RegExp(`:${spec.port}\\b`).test(sockets),
  }));
  const installed = fs.existsSync(serviceFile) || Boolean(active) || Boolean(enabled);
  return {
    installed,
    running: active === "active" && services.some(s => s.listening),
    enabled: enabled === "enabled",
    source: "systemd",
    serviceName: "opxdr-honeypot",
    services,
    checkedAt: new Date().toISOString(),
  };
}

function publicHostFromUrl(value = "") {
  try { return new URL(value).hostname; } catch { return String(value || "100.86.115.94").replace(/^https?:\/\//, "").split(/[/:]/)[0]; }
}

function isPrivateOrLocalIp(value = "") {
  const ip = String(value || "").trim().toLowerCase();
  if (!ip || ip === "-" || ip === "any" || ip === "localhost" || ip === "::1") return true;
  const parts = ip.split(".").map(n => parseInt(n, 10));
  if (parts.length !== 4 || parts.some(n => Number.isNaN(n))) return false;
  const [a, b] = parts;
  return a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
}

function systemHoneypotGeo() {
  const envLat = parseFloat(process.env.OPXDR_HONEYPOT_LAT || "");
  const envLng = parseFloat(process.env.OPXDR_HONEYPOT_LNG || "");
  if (Number.isFinite(envLat) && Number.isFinite(envLng)) {
    const cc = String(process.env.OPXDR_HONEYPOT_CC || "US").toUpperCase();
    const base = GEO_BY_CC_SERVER[cc] || GEO_BY_CC_SERVER.US;
    return { lat: envLat, lng: envLng, cc, name: process.env.OPXDR_HONEYPOT_NAME || base.name, systemLocation: "env" };
  }

  const tz = process.env.TZ || Intl.DateTimeFormat().resolvedOptions().timeZone || "";
  if (/New_York|Detroit|Toronto|Montreal|Eastern/i.test(tz)) return { lat: 40.7128, lng: -74.0060, cc: "US", name: "New York, USA", systemLocation: "timezone" };
  if (/Chicago|Central/i.test(tz)) return { lat: 41.8781, lng: -87.6298, cc: "US", name: "Chicago, USA", systemLocation: "timezone" };
  if (/Denver|Mountain/i.test(tz)) return { lat: 39.7392, lng: -104.9903, cc: "US", name: "Denver, USA", systemLocation: "timezone" };
  if (/Los_Angeles|Pacific/i.test(tz)) return { lat: 34.0522, lng: -118.2437, cc: "US", name: "Los Angeles, USA", systemLocation: "timezone" };
  return { lat: 38.9, lng: -77.0, cc: "US", name: "United States", systemLocation: "default" };
}


function agentHoneypotLocation(agent = {}) {
  const host = agent.name || os.hostname() || "soc-admin";
  const ip = agent.ip && agent.ip !== "any" ? agent.ip : publicHostFromUrl(process.env.OPXDR_PUBLIC_URL || "http://100.86.115.94:8787");
  const geo = isPrivateOrLocalIp(ip) ? systemHoneypotGeo() : ipToCyberGeo(ip);
  return { host, ...geo, ip };
}

async function agentDestination(agentId, serverUrl) {
  let host = os.hostname() || "soc-admin";
  let ip = publicHostFromUrl(serverUrl || process.env.OPXDR_PUBLIC_URL || "http://100.86.115.94:8787");
  if (agentId && agentId !== "local") {
    try {
      const j = await wazuh("/agents", { limit: 500, offset: 0 });
      const found = (j?.data?.affected_items || []).find(a => String(a.id) === String(agentId));
      if (found) {
        host = found.name || host;
        if (found.ip && found.ip !== "any") ip = found.ip;
      }
    } catch {}
  }
  const geo = isPrivateOrLocalIp(ip) ? systemHoneypotGeo() : ipToCyberGeo(ip);
  return { host, ...geo, ip };
}

function alertToHoneypotEvent(alert, destination) {
  const full = alert.fullLog || alert.raw?.full_log || "";
  if (!/OPXDR_HONEYPOT/.test(full)) return null;
  const kv = parseKvLog(full);
  if (kv.preview === "listener_started" || kv.remote === "0.0.0.0" || String(kv.preview || "").startsWith("OPXDR")) return null;
  const service = kv.service || "honeypot";
  const meta = honeypotMetaForService(service);
  const src = ipToCyberGeo(kv.remote || alert.srcIp || "-");
  const dst = { ...destination, port: servicePort(service, kv.port), service };
  return {
    id: `honeypot-${alert.id || crypto.createHash("sha1").update(full).digest("hex").slice(0, 12)}`,
    type: "honeypot",
    severity: String(meta.severity || alert.severity || "medium").toLowerCase(),
    src,
    dst,
    cve: kv.cve || meta.cve,
    malware: kv.malware || meta.malware,
    actor: kv.actor || meta.actor,
    tactic: meta.tactic,
    mitre: meta.mitre,
    timestamp: alert.time || new Date().toISOString(),
    createdAt: Date.parse(alert.time || new Date()) || Date.now(),
    color: "#ff7a18",
    feed: "OPXDR Honeypot",
    agentId: kv.agent_id || alert.agentId,
    service,
    raw: alert,
  };
}

async function loadHoneypotCyberEvents({ limit = 100, since = null, agentIds = [] } = {}) {
  const alerts = [];
  const agentFilter = new Set((agentIds || []).map(v => String(v)).filter(Boolean));
  const sinceMs = since ? new Date(since).getTime() : 0;
  for (const a of injectedAlerts) {
    if (/OPXDR_HONEYPOT/.test(a.fullLog || "") && (!sinceMs || new Date(a.time || 0).getTime() > sinceMs)) alerts.push(a);
  }
  if (WAZUH_INDEXER_PASS) {
    try {
      const result = await queryIndexer({ minLevel: 1, size: Math.max(limit * 4, 100), after: since });
      for (const hit of result.hits?.hits || []) {
        const parsed = parseIndexerHit(hit);
        if (parsed && /OPXDR_HONEYPOT/.test(parsed.fullLog || "")) alerts.push(parsed);
      }
    } catch (e) {
      console.warn("[honeypot] indexer query failed:", e.message);
    }
  }
  if (fs.existsSync(WAZUH_ALERTS_LOG) && alerts.length < limit) {
    try {
      const tail = await new Promise((resolve, reject) => {
        const proc = spawn("tail", ["-n", String(limit * 8), WAZUH_ALERTS_LOG]);
        let buf = "";
        proc.stdout.on("data", d => buf += d.toString());
        proc.on("close", () => resolve(buf));
        proc.on("error", reject);
      });
      for (const line of tail.split("\n")) {
        if (!line.includes("OPXDR_HONEYPOT")) continue;
        const parsed = parseAlertLine(line);
        if (parsed && (!sinceMs || new Date(parsed.time || 0).getTime() > sinceMs)) alerts.push(parsed);
      }
    } catch (e) {
      console.warn("[honeypot] file tail failed:", e.message);
    }
  }
  const seen = new Set();
  const events = [];
  for (const alert of alerts.sort((a, b) => new Date(b.time || 0) - new Date(a.time || 0))) {
    const kv = parseKvLog(alert.fullLog || "");
    const destination = await agentDestination(kv.agent_id || alert.agentId, kv.opxdr_server);
    const event = alertToHoneypotEvent(alert, destination);
    if (!event || (agentFilter.size && !agentFilter.has(String(event.agentId))) || seen.has(event.id)) continue;
    seen.add(event.id);
    events.push(event);
    if (events.length >= limit) break;
  }
  return events;
}

function siemAgentInstallScript({ agentId, agentName, serverUrl }) {
  const pyAgentId = JSON.stringify(agentId);
  const pyAgentName = JSON.stringify(agentName || agentId);
  const pyServerUrl = JSON.stringify(serverUrl);
  const agentPy = `#!/usr/bin/env python3
import hashlib
import ipaddress
import json
import os
import platform
import socket
import subprocess
import syslog
import time
import urllib.error
import urllib.request

AGENT_ID = ${pyAgentId}
AGENT_NAME = ${pyAgentName}
OPXDR_SERVER = ${pyServerUrl}.rstrip("/")
INTERVAL = int(os.environ.get("OPXDR_SIEM_INTERVAL", "30"))
WATCH_PATHS = ["/etc/passwd", "/etc/group", "/etc/ssh/sshd_config", "/etc/sudoers"]
AUTH_LOGS = ["/var/log/auth.log", "/var/log/secure"]
HONEYPOT_LOGS = [
    "/home/cowrie/cowrie/var/log/cowrie/cowrie.json",
    "/home/cowrie/cowrie/var/log/cowrie/cowrie.log",
    "/opt/cowrie/var/log/cowrie/cowrie.json",
    "/opt/cowrie/var/log/cowrie/cowrie.log",
    "/var/log/cowrie/cowrie.json",
    "/var/log/cowrie/cowrie.log",
    "/var/log/syslog",
    "/var/log/messages",
]

def clean(value, limit=500):
    text = str(value if value is not None else "-").replace("\\n", " ").replace("\\r", " ")
    return text[:limit]

def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=4)
    except Exception:
        return ""

def primary_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def sha256_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        st = os.stat(path)
        return {"path": path, "sha256": h.hexdigest(), "size": st.st_size, "mtime": int(st.st_mtime)}
    except Exception as exc:
        return {"path": path, "error": clean(exc, 160)}

def process_snapshot():
    lines = run(["ps", "-eo", "pid,ppid,user,comm,args", "--no-headers"]).splitlines()[:80]
    return [clean(line, 260) for line in lines]

def network_snapshot():
    out = run(["ss", "-H", "-tulpen"]) or run(["netstat", "-tulpen"])
    return [clean(line, 260) for line in out.splitlines()[:80]]

def auth_snapshot():
    events = []
    needles = ("failed password", "accepted password", "accepted publickey", "sudo:", "session opened", "invalid user")
    for path in AUTH_LOGS:
        if not os.path.exists(path):
            continue
        for line in run(["tail", "-n", "80", path]).splitlines():
            low = line.lower()
            if any(n in low for n in needles):
                events.append({"path": path, "line": clean(line, 320)})
    return events[-40:]

def source_class(value):
    try:
        ip = ipaddress.ip_address(str(value))
        if ip.is_loopback:
            return "loopback"
        if ip.is_private:
            return "private_lab"
        if ip.is_global:
            return "public"
        return "unknown"
    except Exception:
        return "unknown"

def honeypot_snapshot():
    events = []
    src_ips = set()
    public_src_ips = set()
    source_classes = {}
    auth_failures = 0
    commands = []
    lines = []
    for path in HONEYPOT_LOGS:
        if not os.path.exists(path):
            continue
        for line in run(["tail", "-n", "200", path]).splitlines():
            lines.append((path, line))
    for line in run(["journalctl", "-u", "opxdr-honeypot.service", "-n", "200", "--no-pager"]).splitlines():
        lines.append(("journalctl:opxdr-honeypot.service", line))
    for path, line in lines:
        low = line.lower()
        if not any(n in low for n in ("opxdr_honeypot", "cowrie.", "login", "failed", "command", "connection", "direct-tcpip")):
            continue
        item = {"path": path, "line": clean(line, 500)}
        remote_ip = None
        try:
            parsed = json.loads(line)
            item["eventid"] = parsed.get("eventid")
            item["src_ip"] = parsed.get("src_ip")
            item["username"] = parsed.get("username")
            item["input"] = parsed.get("input")
            if parsed.get("src_ip"):
                remote_ip = str(parsed.get("src_ip"))
                src_ips.add(remote_ip)
            if "login.failed" in str(parsed.get("eventid", "")):
                auth_failures += 1
            if parsed.get("input"):
                commands.append(clean(parsed.get("input"), 120))
        except Exception:
            for token in line.split():
                if token.startswith("remote=") and token.split("=", 1)[1] not in ("0.0.0.0", "-", "unknown"):
                    remote_ip = token.split("=", 1)[1]
                    src_ips.add(remote_ip)
            if "login.failed" in low or "failed password" in low:
                auth_failures += 1
        if remote_ip:
            cls = source_class(remote_ip)
            item["source_class"] = cls
            source_classes[cls] = source_classes.get(cls, 0) + 1
            if cls == "public":
                public_src_ips.add(remote_ip)
        events.append(item)
    return {
        "events": events[-80:],
        "event_count": len(events),
        "source_ips": sorted(src_ips)[:40],
        "source_ip_count": len(src_ips),
        "public_source_ips": sorted(public_src_ips)[:40],
        "public_source_ip_count": len(public_src_ips),
        "source_classes": source_classes,
        "real_external": len(public_src_ips) > 0,
        "auth_failures": auth_failures,
        "commands": commands[-20:],
    }

def payload(kind):
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    uptime = None
    if os.path.exists("/proc/uptime"):
        try:
            uptime = int(float(open("/proc/uptime").read().split()[0]))
        except Exception:
            uptime = None
    return {
        "marker": "OPXDR_SIEM_TELEMETRY",
        "agent_version": "${OPXDR_SIEM_AGENT_VERSION}",
        "telemetry_schema": "opxdr.siem.telemetry.v1",
        "kind": kind,
        "agent_id": AGENT_ID,
        "agent_name": AGENT_NAME,
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "ip": primary_ip(),
        "time": now,
        "system": {
            "os": platform.platform(),
            "kernel": platform.release(),
            "arch": platform.machine(),
            "uptime_seconds": uptime,
            "loadavg": os.getloadavg() if hasattr(os, "getloadavg") else None,
        },
        "processes": process_snapshot(),
        "network": network_snapshot(),
        "auth": auth_snapshot(),
        "honeypot": honeypot_snapshot(),
        "files": [sha256_file(p) for p in WATCH_PATHS],
    }

def emit(data):
    top_ports = ",".join([clean(x, 80).split()[4] if len(clean(x, 80).split()) > 4 else clean(x, 80) for x in (data.get("network") or [])[:12]])
    hp = data.get("honeypot") or {}
    summary = "OPXDR_SIEM_TELEMETRY agent_id=%s agent_name=%s agent_version=%s schema=%s kind=%s host=%s ip=%s processes=%s listeners=%s active_ports=%s auth_events=%s honeypot_events=%s honeypot_src_ips=%s public_src_ips=%s real_external=%s auth_failures=%s honeypot_commands=%s files=%s" % (
        clean(data.get("agent_id")),
        clean(data.get("agent_name")),
        clean(data.get("agent_version")),
        clean(data.get("telemetry_schema")),
        clean(data.get("kind")),
        clean(data.get("hostname")),
        clean(data.get("ip")),
        len(data.get("processes") or []),
        len(data.get("network") or []),
        clean(top_ports, 260),
        len(data.get("auth") or []),
        int(hp.get("event_count") or 0),
        int(hp.get("source_ip_count") or 0),
        int(hp.get("public_source_ip_count") or 0),
        str(bool(hp.get("real_external"))).lower(),
        int(hp.get("auth_failures") or 0),
        len(hp.get("commands") or []),
        len(data.get("files") or []),
    )
    syslog.syslog(syslog.LOG_INFO, summary)
    print(data["time"], summary, flush=True)
    body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        OPXDR_SERVER + "/api/opxdr-siem-agent/telemetry",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=6).read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        syslog.syslog(syslog.LOG_WARNING, "OPXDR_SIEM_TELEMETRY post_failed agent_id=%s error=%s" % (clean(AGENT_ID), clean(exc, 180)))

def main():
    emit(payload("startup"))
    while True:
        emit(payload("heartbeat"))
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
`;

  return [
    "#!/usr/bin/env bash",
    "set -euo pipefail",
    "INSTALL_DIR=/opt/opxdr-siem-agent",
    "AGENT_FILE=$INSTALL_DIR/opxdr-siem-agent.py",
    "SERVICE_FILE=/etc/systemd/system/opxdr-siem-agent.service",
    "mkdir -p $INSTALL_DIR",
    "cat > $AGENT_FILE <<'PYAGENT'",
    agentPy,
    "PYAGENT",
    "chmod 0755 $AGENT_FILE",
    "cat > $SERVICE_FILE <<'UNIT'",
    "[Unit]",
    "Description=OPXDR SIEM Telemetry Agent",
    "After=network-online.target rsyslog.service",
    "Wants=network-online.target",
    "",
    "[Service]",
    "Type=simple",
    "ExecStart=/usr/bin/env python3 /opt/opxdr-siem-agent/opxdr-siem-agent.py",
    "Restart=always",
    "RestartSec=5",
    "NoNewPrivileges=true",
    "PrivateTmp=true",
    "",
    "[Install]",
    "WantedBy=multi-user.target",
    "UNIT",
    "systemctl daemon-reload",
    "systemctl enable --now opxdr-siem-agent.service",
    "systemctl --no-pager --full status opxdr-siem-agent.service || true",
    "echo OPXDR SIEM telemetry agent installed for agent " + agentId,
    "echo Telemetry marker: OPXDR_SIEM_TELEMETRY",
    "",
  ].join("\n");
}

app.post(["/api/opxdr-siem-agent/telemetry", "/api/siem-agent/telemetry"], async (req, res) => {
  try {
    const event = {
      receivedAt: new Date().toISOString(),
      remoteAddress: req.ip,
      ...req.body,
      marker: "OPXDR_SIEM_TELEMETRY",
    };
    await fsp.appendFile(SIEM_AGENT_TELEMETRY_LOG, JSON.stringify(event) + "\n");
    const detections = evaluateSiemTelemetryDetections(event);
    res.json({ ok: true, receivedAt: event.receivedAt, detections: detections.map(a => ({ id: a.id, ruleId: a.ruleId, severity: a.severity })) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get(["/api/opxdr-siem-agent/install.sh", "/api/siem-agent/install.sh"], (req, res) => {
  const agentId = String(req.query.agentId || "local").replace(/[^a-zA-Z0-9_.:-]/g, "_").slice(0, 80) || "local";
  const agentName = String(req.query.name || agentId).replace(/[\r\n]/g, " ").slice(0, 120) || agentId;
  const serverUrl = process.env.OPXDR_PUBLIC_URL || `${req.protocol}://${req.get("host")}`;
  const script = siemAgentInstallScript({ agentId, agentName, serverUrl });
  res.setHeader("Content-Type", "text/x-shellscript; charset=utf-8");
  res.setHeader("Content-Disposition", "attachment; filename=opxdr-siem-agent-install.sh");
  res.send(script);
});

const HONEYPOT_SERVICE_CATALOG = {
  ssh: { id: "ssh", name: "SSH Credential Trap", proto: "TCP", port: 2222, tactic: "Credential Access" },
  http: { id: "http", name: "HTTP Web Trap", proto: "TCP", port: 8080, tactic: "Initial Access" },
  ftp: { id: "ftp", name: "FTP Drop Trap", proto: "TCP", port: 2121, tactic: "Credential Access" },
  smb: { id: "smb", name: "SMB Share Lure", proto: "TCP", port: 4455, tactic: "Lateral Movement" },
  smtp: { id: "smtp", name: "SMTP Relay Trap", proto: "TCP", port: 2525, tactic: "Phishing" },
};

function selectedHoneypotServices(raw) {
  const requested = String(raw || "ssh,http,ftp,smb,smtp").split(",").map(v => v.trim().toLowerCase()).filter(Boolean);
  const unique = [...new Set(requested)].filter(id => HONEYPOT_SERVICE_CATALOG[id]);
  return (unique.length ? unique : Object.keys(HONEYPOT_SERVICE_CATALOG)).map(id => HONEYPOT_SERVICE_CATALOG[id]);
}

function honeypotInstallScript({ agentId, services, serverUrl }) {
  const pyServiceJson = JSON.stringify(JSON.stringify(services));
  const pyAgentId = JSON.stringify(agentId);
  const pyServerUrl = JSON.stringify(serverUrl);
  const agentPy = `#!/usr/bin/env python3
import json
import os
import ipaddress
import signal
import socket
import syslog
import threading
import time
import urllib.parse

SERVICES = json.loads(${pyServiceJson})
AGENT_ID = ${pyAgentId}
OPXDR_SERVER = ${pyServerUrl}
STOP = threading.Event()
DECOY_ROOT = "/opt/opxdr-honeypot/decoys"

BANNERS = {
    "ssh": b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\\r\\nlogin: ",
    "ftp": b"220 files-backup01 FTP service ready\\r\\nName (files-backup01:anonymous): ",
    "smtp": b"220 mail-gateway01 ESMTP Postfix\\r\\n",
    "smb": b"\\x00\\x00\\x00\\x55SMB honeypot negotiation required\\r\\n",
}

DECOY_FILES = {
    "backup/db-backup-2026-08-23.sql": "-- OPXDR DECOY ONLY - NOT REAL DATA\\n-- canary_id=OPXDR-CANARY-DB-001\\nCREATE USER 'backup_reader'@'%' IDENTIFIED BY 'not-a-real-password';\\n",
    "backup/vpn-users.csv": "user,role,last_login,canary_id\\nsvc-backup,readonly,2026-08-20,OPXDR-CANARY-VPN-002\\n",
    "config/.env": "OPXDR_DECOY=true\\nCANARY_ID=OPXDR-CANARY-ENV-003\\nAWS_ACCESS_KEY_ID=AKIAFAKEDECOY000000\\nAWS_SECRET_ACCESS_KEY=not-a-real-secret-do-not-use\\n",
    "config/id_rsa": "-----BEGIN OPXDR DECOY PRIVATE KEY-----\\nCANARY_ID=OPXDR-CANARY-SSH-004\\nnot-a-real-private-key\\n-----END OPXDR DECOY PRIVATE KEY-----\\n",
    "config/kubernetes-admin.conf": "apiVersion: v1\\nkind: Config\\ncurrent-context: opxdr-decoy\\nusers:\\n- name: decoy-admin\\n  user:\\n    token: OPXDR-CANARY-K8S-005-NOT-A-REAL-TOKEN\\n",
}

HTTP_LURES = {
    "/": ("text/html", "<html><head><title>Edge Gateway</title></head><body><h1>Edge Gateway</h1><p>Authentication required.</p><a href='/admin/login'>Admin login</a></body></html>"),
    "/admin": ("text/html", "<html><head><title>Admin Console</title></head><body><h1>Admin Console</h1><form method='post' action='/admin/login'><input name='username' placeholder='username'><input name='password' type='password' placeholder='password'><button>Sign in</button></form></body></html>"),
    "/admin/login": ("text/html", "<html><head><title>Admin Console</title></head><body><h1>Admin Console</h1><p>Invalid session. Sign in again.</p><form method='post'><input name='username' placeholder='username'><input name='password' type='password' placeholder='password'><button>Sign in</button></form></body></html>"),
    "/backup/": ("text/html", "<html><head><title>Index of /backup/</title></head><body><h1>Index of /backup/</h1><a href='/backup/db-backup-2026-08-23.sql'>db-backup-2026-08-23.sql</a><br><a href='/backup/vpn-users.csv'>vpn-users.csv</a></body></html>"),
    "/backup/db-backup-2026-08-23.sql": ("text/plain", DECOY_FILES["backup/db-backup-2026-08-23.sql"]),
    "/backup/vpn-users.csv": ("text/csv", DECOY_FILES["backup/vpn-users.csv"]),
    "/.env": ("text/plain", DECOY_FILES["config/.env"]),
    "/config/.env": ("text/plain", DECOY_FILES["config/.env"]),
    "/id_rsa": ("text/plain", DECOY_FILES["config/id_rsa"]),
    "/.ssh/id_rsa": ("text/plain", DECOY_FILES["config/id_rsa"]),
    "/kubernetes-admin.conf": ("text/plain", DECOY_FILES["config/kubernetes-admin.conf"]),
}

def clean(value):
    text = str(value or "-").replace("\\n", " ").replace("\\r", " ")
    return text[:220]

def source_class(value):
    try:
        ip = ipaddress.ip_address(str(value))
        if ip.is_loopback:
            return "loopback"
        if ip.is_private:
            return "private_lab"
        if ip.is_global:
            return "public"
        return "unknown"
    except Exception:
        return "unknown"

def emit(service, port, remote, payload):
    preview = clean(payload.decode("utf-8", "replace") if isinstance(payload, bytes) else payload)
    cls = source_class(remote)
    msg = "OPXDR_HONEYPOT agent_id=%s service=%s port=%s proto=tcp remote=%s source_class=%s real_external=%s opxdr_server=%s preview=%s" % (
        clean(AGENT_ID), clean(service), clean(port), clean(remote), clean(cls), str(cls == "public").lower(), clean(OPXDR_SERVER), preview
    )
    syslog.syslog(syslog.LOG_INFO, msg)
    print(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), msg, flush=True)

def write_decoy_files():
    os.makedirs(DECOY_ROOT, exist_ok=True)
    for rel, body in DECOY_FILES.items():
        path = os.path.join(DECOY_ROOT, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        os.chmod(path, 0o640)
    emit("filesystem", 0, "0.0.0.0", "decoy_files_ready canary_ids=OPXDR-CANARY-DB-001,OPXDR-CANARY-VPN-002,OPXDR-CANARY-ENV-003,OPXDR-CANARY-SSH-004,OPXDR-CANARY-K8S-005")

def http_response(payload):
    text = payload.decode("utf-8", "replace") if isinstance(payload, bytes) else str(payload or "")
    first = text.split("\\n", 1)[0].strip()
    parts = first.split()
    method = parts[0].upper() if parts else "GET"
    raw_path = parts[1] if len(parts) > 1 else "/"
    path = urllib.parse.urlparse(raw_path).path or "/"
    content_type, body = HTTP_LURES.get(path, ("text/html", "<html><head><title>401 Unauthorized</title></head><body><h1>401 Unauthorized</h1><p>Authentication required.</p></body></html>"))
    status = "200 OK" if path in HTTP_LURES else "401 Unauthorized"
    marker = ""
    if path in HTTP_LURES and path not in ("/", "/admin", "/admin/login", "/backup/"):
        marker = " canary_access=true canary_path=%s" % clean(path, 120)
    return (("HTTP/1.1 %s\\r\\nServer: nginx/1.18.0\\r\\nContent-Type: %s\\r\\nConnection: close\\r\\nWWW-Authenticate: Basic realm=admin\\r\\nContent-Length: %d\\r\\n\\r\\n%s" % (status, content_type, len(body.encode("utf-8")), body)).encode("utf-8"), "http_method=%s request_path=%s%s raw=%s" % (clean(method, 16), clean(path, 140), marker, clean(first, 180)))

def handle_client(service, port, conn, addr):
    remote = addr[0] if addr else "unknown"
    try:
        conn.settimeout(4)
        if service == "http":
            payload = conn.recv(2048)
            response, summary = http_response(payload)
            emit(service, port, remote, summary)
            conn.sendall(response)
            return
        banner = BANNERS.get(service, b"OPXDR honeypot service ready\\r\\n")
        if banner:
            conn.sendall(banner)
        payload = conn.recv(2048)
        emit(service, port, remote, payload)
        if service == "ftp":
            conn.sendall(b"530 Login incorrect.\\r\\n")
        elif service == "smtp":
            conn.sendall(b"550 relay denied\\r\\n")
    except Exception as exc:
        emit(service, port, remote, "handler_error=" + str(exc))
    finally:
        try:
            conn.close()
        except Exception:
            pass

def listener(spec):
    service = spec["id"]
    port = int(spec["port"])
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(50)
    sock.settimeout(1)
    emit(service, port, "0.0.0.0", "listener_started")
    while not STOP.is_set():
        try:
            conn, addr = sock.accept()
            threading.Thread(target=handle_client, args=(service, port, conn, addr), daemon=True).start()
        except socket.timeout:
            continue
        except Exception as exc:
            emit(service, port, "0.0.0.0", "listener_error=" + str(exc))
            time.sleep(2)
    sock.close()

def shutdown(_signum, _frame):
    STOP.set()

signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT, shutdown)
write_decoy_files()
threads = []
for spec in SERVICES:
    t = threading.Thread(target=listener, args=(spec,), daemon=True)
    t.start()
    threads.append(t)
while not STOP.is_set():
    time.sleep(1)
`;

  return [
    "#!/usr/bin/env bash",
    "set -euo pipefail",
    "INSTALL_DIR=/opt/opxdr-honeypot",
    "AGENT_FILE=$INSTALL_DIR/opxdr-honeypot-agent.py",
    "SERVICE_FILE=/etc/systemd/system/opxdr-honeypot.service",
    "mkdir -p $INSTALL_DIR",
    "cat > $AGENT_FILE <<'PYAGENT'",
    agentPy,
    "PYAGENT",
    "chmod 0755 $AGENT_FILE",
    "cat > $SERVICE_FILE <<'UNIT'",
    "[Unit]",
    "Description=OPXDR Honeypot Telemetry Agent",
    "After=network-online.target rsyslog.service",
    "Wants=network-online.target",
    "",
    "[Service]",
    "Type=simple",
    "ExecStart=/usr/bin/env python3 /opt/opxdr-honeypot/opxdr-honeypot-agent.py",
    "Restart=always",
    "RestartSec=3",
    "NoNewPrivileges=true",
    "PrivateTmp=true",
    "",
    "[Install]",
    "WantedBy=multi-user.target",
    "UNIT",
    "systemctl daemon-reload",
    "systemctl enable --now opxdr-honeypot.service",
    "systemctl --no-pager --full status opxdr-honeypot.service || true",
    "echo OPXDR honeypot agent installed for agent " + agentId + " with services: " + services.map(s => s.id).join(","),
    "echo Telemetry marker: OPXDR_HONEYPOT",
    "",
  ].join("\n");
}

app.get("/api/honeypot-agent/install.sh", (req, res) => {
  const agentId = String(req.query.agentId || "local").replace(/[^a-zA-Z0-9_.:-]/g, "_").slice(0, 80) || "local";
  const services = selectedHoneypotServices(req.query.services);
  const serverUrl = process.env.OPXDR_PUBLIC_URL || `${req.protocol}://${req.get("host")}`;
  const script = honeypotInstallScript({ agentId, services, serverUrl });
  res.setHeader("Content-Type", "text/x-shellscript; charset=utf-8");
  res.setHeader("Content-Disposition", "attachment; filename=opxdr-honeypot-agent-install.sh");
  res.send(script);
});

let rulesCache = null;
let rulesCacheTime = 0;
app.get("/api/rules", async (req, res) => {
  const refresh = req.query.refresh === "1";
  if (!refresh && rulesCache && Date.now() - rulesCacheTime < 60_000) {
    return res.json(rulesCache);
  }
  const [local, live] = await Promise.all([loadLocalRules(), loadWazuhApiRules()]);
  const groups = {};
  for (const r of [...local, ...live]) {
    const k = r.group || "other";
    if (!groups[k]) groups[k] = { key: k, label: r.groupLabel || k, color: r.groupColor || "#64748b", icon: r.groupIcon || "📂", rules: [] };
    groups[k].rules.push(r);
  }
  rulesCache = { groups, total_local: local.length, total_live: live.length, generated_at: new Date().toISOString() };
  rulesCacheTime = Date.now();
  res.json(rulesCache);
});

app.get("/api/rules/:id", async (req, res) => {
  const all = (await loadLocalRules()).concat(await loadWazuhApiRules());
  const rule = all.find((r) => r.id === req.params.id || r.wazuhRuleId === req.params.id);
  if (!rule) return res.status(404).json({ error: "not found" });
  let raw = "";
  if (rule.filePath) { try { raw = await fsp.readFile(rule.filePath, "utf8"); } catch {} }
  res.json({ ...rule, raw });
});

// IR playbooks on disk
app.get("/api/playbooks", async (_req, res) => {
  const all = await walk(RULES_LOCAL_ROOT);
  const pbs = [];
  for (const f of all) {
    const lower = f.toLowerCase();
    if (!(lower.endsWith(".yml") || lower.endsWith(".yaml"))) continue;
    if (!/(playbook|ir_|response|containment|triage|close_case|validate_)/i.test(f)) continue;
    let preview = "";
    try { preview = (await fsp.readFile(f, "utf8")).slice(0, 600); } catch {}
    pbs.push({ name: path.basename(f), path: f, preview });
  }
  res.json({ playbooks: pbs, count: pbs.length });
});

// ─── Alerts: recent + SSE tail ────────────────────────────────────────────
function parseAlertLine(line) {
  try {
    const a = JSON.parse(line);
    const rule = a.rule || {};
    const data = a.data || {};
    const lvl = rule.level || 0;
    const sev = sevFromLevel(lvl);
    const techs = rule?.mitre?.id?.join(",") || "—";
    const tactic = deriveTactic((rule.groups || []).join(" ") + " " + (rule.description || ""));
    return {
      id: `DET-${(a.timestamp || "").replace(/[^0-9]/g, "").slice(0, 14)}-${(rule.id || "0").padStart(4, "0")}`,
      ruleId: `WAZ-${rule.id || "?"}`,
      ruleName: rule.description || "Wazuh alert",
      severity: sev,
      level: lvl,
      tactic,
      mitre: techs,
      time: a.timestamp || new Date().toISOString(),
      srcIp: data.srcip || data.src_ip || "—",
      dstIp: data.dstip || data.dst_ip || "—",
      account: data.srcuser || data.dstuser || data.user || "—",
      host: a.agent?.name || "—",
      iocs: [
        data.srcip && { t: "IP", v: data.srcip },
        data.url && { t: "URL", v: data.url },
        data.command && { t: "CMD", v: data.command },
        rule.id && { t: "RuleID", v: String(rule.id) },
      ].filter(Boolean),
      groups: rule.groups || [],
      raw: a,
    };
  } catch {
    return null;
  }
}

// Minimum Wazuh level to surface in the live feed (12 = HIGH, 15 = CRITICAL only).
// Override via ALERT_MIN_LEVEL in .env or ?min_level= query param.
const ALERT_MIN_LEVEL = parseInt(process.env.ALERT_MIN_LEVEL || "1", 10);

// ─── Injected alerts (POST /api/alerts/inject) ────────────────────────────
const alertEmitter = new EventEmitter();
const injectedAlerts = []; // ring buffer — capped at 500

// ─── Persistent High/Critical Alert Store ─────────────────────────────────
const PERSISTED_ALERTS_FILE = path.join(__dirname, "..", ".persisted-alerts.json");
let persistedAlerts = [];

function loadPersistedAlerts() {
  try {
    if (fs.existsSync(PERSISTED_ALERTS_FILE)) {
      const raw = fs.readFileSync(PERSISTED_ALERTS_FILE, "utf-8");
      persistedAlerts = JSON.parse(raw);
      if (!Array.isArray(persistedAlerts)) persistedAlerts = [];
      console.log(`[persist] loaded ${persistedAlerts.length} high/critical alerts from disk`);
    }
  } catch (e) {
    console.warn("[persist] could not load persisted alerts:", e.message);
    persistedAlerts = [];
  }
}

function savePersistedAlerts() {
  try {
    fs.writeFileSync(PERSISTED_ALERTS_FILE, JSON.stringify(persistedAlerts, null, 2));
  } catch (e) {
    console.warn("[persist] could not save persisted alerts:", e.message);
  }
}

async function backfillHighCriticalAlerts() {
  if (!WAZUH_INDEXER_PASS) return;
  try {
    const result = await queryIndexer({ minLevel: 7, size: 10000 });
    const hits = (result.hits?.hits || []).map(parseIndexerHit).filter(Boolean);
    const seen = new Set(persistedAlerts.map(a => a.id));
    let added = 0;
    for (const a of hits) {
      if (a.severity === "LOW") continue;
      if (!seen.has(a.id)) {
        persistedAlerts.push(a);
        seen.add(a.id);
        added++;
      }
    }
    if (added > 0) {
      console.log(`[persist] backfill added ${added} new medium+ alerts (total: ${persistedAlerts.length})`);
      savePersistedAlerts();
    }
  } catch (e) {
    console.warn("[persist] backfill failed:", e.message);
  }
}

async function pollHighCriticalAlerts() {
  if (!WAZUH_INDEXER_PASS) return;
  const lastTs = persistedAlerts.length > 0
    ? [...persistedAlerts].sort((a, b) => b.time.localeCompare(a.time))[0].time
    : new Date(Date.now() - 86400000).toISOString();
  try {
    const result = await queryIndexer({ minLevel: 7, size: 500, after: lastTs });
    const hits = (result.hits?.hits || []).map(parseIndexerHit).filter(Boolean);
    const seen = new Set(persistedAlerts.map(a => a.id));
    let added = 0;
    for (const a of hits) {
      if (a.severity === "LOW") continue;
      if (!seen.has(a.id)) {
        persistedAlerts.push(a);
        seen.add(a.id);
        added++;
      }
    }
    if (added > 0) {
      console.log(`[persist] poll added ${added} new medium+ alerts (total: ${persistedAlerts.length})`);
      savePersistedAlerts();
    }
  } catch (e) {
    console.warn("[persist] poll failed:", e.message);
  }
}

// ─── Wazuh Indexer (OpenSearch) ───────────────────────────────────────────
const WAZUH_INDEXER_URL   = process.env.WAZUH_INDEXER_URL   || "https://localhost:9200";
const WAZUH_INDEXER_USER  = process.env.WAZUH_INDEXER_USER  || "admin";
const WAZUH_INDEXER_PASS  = process.env.WAZUH_INDEXER_PASS  || "";
const WAZUH_INDEXER_INDEX = process.env.WAZUH_INDEXER_INDEX || "wazuh-alerts-4.x-*";

async function queryIndexer({ minLevel = ALERT_MIN_LEVEL, size = 50, after = null } = {}) {
  const auth = Buffer.from(`${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASS}`).toString("base64");
  const filter = [{ range: { "rule.level": { gte: minLevel } } }];
  if (after) filter.push({ range: { timestamp: { gt: after } } });
  const r = await fetch(
    `${WAZUH_INDEXER_URL}/${WAZUH_INDEXER_INDEX}/_search`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Basic ${auth}` },
      body: JSON.stringify({
        size,
        query: { bool: { filter } },
        sort: [{ timestamp: { order: "desc" } }],
      }),
      agent: insecureAgent,
    }
  );
  if (!r.ok) throw new Error(`Indexer ${r.status}: ${(await r.text()).slice(0, 200)}`);
  return r.json();
}

function parseIndexerHit(hit) {
  const src = hit._source || {};
  const rule = src.rule || {};
  const data = src.data || {};
  const agent = src.agent || {};
  const lvl = rule.level || 0;
  const sev = sevFromLevel(lvl);
  const techs = rule?.mitre?.id?.join(",") || "—";
  const tactic = deriveTactic((rule.groups || []).join(" ") + " " + (rule.description || ""));
  const ts = src.timestamp || new Date().toISOString();
  const iocs = [
    data.srcip && { t: "IP", v: data.srcip },
    data.src_ip && { t: "IP", v: data.src_ip },
    data.dstip && { t: "IP", v: data.dstip },
    data.url && { t: "URL", v: data.url },
    data.md5 && { t: "Hash", v: data.md5 },
    data.sha256 && { t: "Hash", v: data.sha256 },
    data.command && { t: "CMD", v: data.command },
    (data.srcuser || data.dstuser || data.user) && { t: "Account", v: data.srcuser || data.dstuser || data.user },
    rule.id && { t: "RuleID", v: String(rule.id) },
  ].filter(Boolean).filter((v, i, a) => a.findIndex(x => x.t === v.t && x.v === v.v) === i);
  return {
    id: hit._id || `DET-${ts.replace(/[^0-9]/g, "").slice(0, 17)}-${String(rule.id || "0").padStart(4, "0")}`,
    ruleId: `WAZ-${rule.id || "?"}`,
    ruleName: rule.description || "Wazuh alert",
    severity: sev,
    level: lvl,
    tactic,
    mitre: techs,
    time: ts,
    srcIp: data.srcip || data.src_ip || "—",
    dstIp: data.dstip || data.dst_ip || "—",
    account: data.srcuser || data.dstuser || data.user || "—",
    host: agent.name || src.hostname || "—",
    agentId: agent.id || "—",
    agentIp: agent.ip || "—",
    location: src.location || "—",
    fullLog: src.full_log || "",
    decoder: src.decoder?.name || "—",
    iocs,
    groups: rule.groups || [],
    raw: src,
  };
}


app.get("/api/honeypot/events", async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || "100", 10) || 100, 500);
    const since = req.query.since || null;
    const agentIds = String(req.query.agentIds || "").split(",").map(v => v.trim()).filter(Boolean);
    const events = await loadHoneypotCyberEvents({ limit, since, agentIds });
    res.json({ events, count: events.length, source: WAZUH_INDEXER_PASS ? "indexer" : "file" });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/alerts/recent", async (req, res) => {
  const limit    = parseInt(req.query.limit     || "500", 10);
  const minLevel = parseInt(req.query.min_level || String(ALERT_MIN_LEVEL), 10);
  const since    = req.query.since || null; // ISO timestamp — when set, filter to alerts after this time

  // Always include injected alerts (newest first, up to limit), filtered by since if given
  const sinceMs = since ? new Date(since).getTime() : 0;
  const injected = [...injectedAlerts]
    .reverse()
    .filter(a => !sinceMs || new Date(a.time || 0).getTime() > sinceMs)
    .slice(0, limit);

  // Primary: Wazuh Indexer (OpenSearch)
  if (WAZUH_INDEXER_PASS) {
    try {
      const result = await queryIndexer({ minLevel, size: limit, after: since });
      const wazuhAlerts = (result.hits?.hits || []).map(parseIndexerHit).filter(Boolean);
      const seen = new Set(injected.map(a => a.id));
      const dedupedWazuh = wazuhAlerts.filter(a => { if(seen.has(a.id))return false; seen.add(a.id); return true; });
      const merged = [...injected, ...dedupedWazuh].slice(0, limit);
      return res.json({ alerts: merged, count: merged.length, min_level: minLevel, since: since || null, source: "indexer" });
    } catch (e) {
      console.warn("[indexer] recent query failed, falling back to file:", e.message);
    }
  }
  // Fallback: tail alerts.json
  try {
    if (!fs.existsSync(WAZUH_ALERTS_LOG)) {
      return res.json({ alerts: injected, count: injected.length, note: "alerts.json not readable — start with sudo or fix perms", source: "injected+file" });
    }
    const tail = spawn("tail", ["-n", String(limit * 4), WAZUH_ALERTS_LOG]);
    let buf = "";
    tail.stdout.on("data", (d) => (buf += d.toString()));
    tail.on("close", () => {
      const fileAlerts = buf
        .split("\n")
        .filter((l) => l.trim())
        .map(parseAlertLine)
        .filter(Boolean)
        .filter((a) => (a.level || 0) >= minLevel)
        .filter((a) => !sinceMs || new Date(a.time || 0).getTime() > sinceMs)
        .slice(-limit)
        .reverse();
      const seen = new Set(injected.map(a => a.id));
      const merged = [...injected, ...fileAlerts.filter(a => !seen.has(a.id))].slice(0, limit);
      res.json({ alerts: merged, count: merged.length, min_level: minLevel, since: since || null, source: "file" });
    });
    tail.on("error", (e) => res.status(500).json({ error: e.message }));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/alerts/stream", (req, res) => {
  res.set({
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  res.flushHeaders();
  res.write(`: connected\n\n`);

  const minLevel = parseInt(req.query.min_level || String(ALERT_MIN_LEVEL), 10);
  res.write(`event: filter\ndata: ${JSON.stringify({ min_level: minLevel, severity: minLevel >= 15 ? "CRITICAL" : "HIGH+" })}\n\n`);

  // Always listen for injected alerts regardless of source
  const seenInjected = new Set(injectedAlerts.map(a => a.id));
  function onInjected(a) {
    if (!seenInjected.has(a.id)) {
      seenInjected.add(a.id);
      res.write(`data: ${JSON.stringify(a)}\n\n`);
    }
  }
  alertEmitter.on("alert", onInjected);

  // Try Indexer first; fall back to file tail on failure
  let indexerFailed = false;
  if (WAZUH_INDEXER_PASS) {
    const seenIds = new Set();
    let lastTs = new Date(Date.now() - 60_000).toISOString();
    const kaTimer = setInterval(() => res.write(`: keepalive\n\n`), 25_000);
    async function pollIndexer() {
      try {
        const result = await queryIndexer({ minLevel, size: 50, after: lastTs });
        indexerFailed = false;
        const hits = (result.hits?.hits || []).reverse();
        for (const hit of hits) {
          const a = parseIndexerHit(hit);
          if (!a || seenIds.has(a.id)) continue;
          seenIds.add(a.id);
          res.write(`data: ${JSON.stringify(a)}\n\n`);
          if (a.time > lastTs) lastTs = a.time;
        }
      } catch (e) {
        console.warn("[indexer] stream poll failed:", e.message);
        // After 3 consecutive failures, switch to file tail fallback
        if (indexerFailed) {
          console.warn("[indexer] switching to file tail fallback");
          clearInterval(pollTimer);
          clearInterval(kaTimer);
          startFileTail();
          return;
        }
        indexerFailed = true;
      }
    }
    pollIndexer();
    const pollTimer = setInterval(pollIndexer, 10_000);
    req.on("close", () => { clearInterval(pollTimer); clearInterval(kaTimer); alertEmitter.off("alert", onInjected); });
    return;
  }

  // Fallback: tail alerts.json
  startFileTail();
  function startFileTail() {
    const canRead = fs.existsSync(WAZUH_ALERTS_LOG);
    if (!canRead) {
      console.warn("[alerts] alerts.json not readable at", WAZUH_ALERTS_LOG);
      res.write(`event: error\ndata: ${JSON.stringify({ msg: "alerts.json not readable at " + WAZUH_ALERTS_LOG, path: WAZUH_ALERTS_LOG })}\n\n`);
      // Try alternative: read via sudo if available, else just keep the connection alive with injected alerts
      const ka = setInterval(() => res.write(`: keepalive\n\n`), 25_000);
      req.on("close", () => { clearInterval(ka); alertEmitter.off("alert", onInjected); });
      return;
    }
    const tail = spawn("tail", ["-F", "-n", "0", WAZUH_ALERTS_LOG]);
    let leftover = "";
    tail.stdout.on("data", (chunk) => {
      const text = leftover + chunk.toString();
      const lines = text.split("\n");
      leftover = lines.pop() || "";
      for (const ln of lines) {
        if (!ln.trim()) continue;
        const a = parseAlertLine(ln);
        if (a && (a.level || 0) >= minLevel) res.write(`data: ${JSON.stringify(a)}\n\n`);
      }
    });
    tail.stderr.on("data", (d) => console.warn("[tail]", d.toString().trim()));
    const ka = setInterval(() => res.write(`: keepalive\n\n`), 25_000);
    req.on("close", () => { clearInterval(ka); tail.kill(); alertEmitter.off("alert", onInjected); });
  }
});

// ─── Alert injection (custom/simulated detections) ────────────────────────
const sevOrder = { LOW: 1, MEDIUM: 5, HIGH: 8, CRITICAL: 12 };

function buildInjectedAlert(b = {}) {
  const sev  = (b.severity || "HIGH").toUpperCase();
  const lvl  = sevOrder[sev] ?? 8;
  const ts   = b.time || new Date().toISOString();
  const uid  = `INJ-${ts.replace(/[^0-9]/g, "").slice(0, 14)}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;

  return {
    id:       uid,
    ruleId:   b.ruleId   || `CUSTOM-${uid.slice(-6)}`,
    ruleName: b.ruleName || b.ruleId || "Custom Detection",
    severity: sev,
    level:    lvl,
    tactic:   b.tactic   || "-",
    mitre:    b.mitre    || "-",
    time:     ts,
    srcIp:    b.srcIp    || "-",
    dstIp:    b.dstIp    || "-",
    account:  b.account  || "-",
    host:     b.host     || "soc-admin",
    agentId:  b.agentId  || "000",
    location: b.location || "testfire",
    fullLog:  b.fullLog  || b.raw_log || "",
    decoder:  b.decoder  || "opxdr-testfire",
    iocs:     Array.isArray(b.iocs) ? b.iocs : [],
    groups:   Array.isArray(b.groups) ? b.groups : [],
    injected: true,
    raw:      b,
  };
}

function recordInjectedAlert(alert) {
  injectedAlerts.push(alert);
  if (injectedAlerts.length > 500) injectedAlerts.shift();
  alertEmitter.emit("alert", alert);
  forwardAlertToSiems(alert).catch((e) => console.warn("[siem-forward]", e.message));
  console.log(`[inject] ${alert.severity} - ${alert.ruleName}`);
  return alert;
}

function createInjectedAlert(b) {
  return recordInjectedAlert(buildInjectedAlert(b));
}

function buildDetectedAlert(b = {}) {
  const alert = buildInjectedAlert(b);
  alert.id = b.id || alert.id.replace(/^INJ-/, "DET-");
  alert.injected = false;
  alert.raw = b.raw || b;
  return alert;
}

function recordDetectedAlert(alert) {
  const exists = (a) => a.id === alert.id;
  if (injectedAlerts.some(exists) || persistedAlerts.some(exists)) return alert;
  injectedAlerts.push(alert);
  if (injectedAlerts.length > 500) injectedAlerts.shift();
  if (alert.severity !== "LOW") {
    persistedAlerts.push(alert);
    if (persistedAlerts.length > 10000) persistedAlerts = persistedAlerts.slice(-10000);
    savePersistedAlerts();
  }
  alertEmitter.emit("alert", alert);
  forwardAlertToSiems(alert).catch((e) => console.warn("[siem-forward]", e.message));
  console.log(`[detect] ${alert.severity} - ${alert.ruleName}`);
  return alert;
}

function telemetryWindowId(ts = new Date()) {
  const t = new Date(ts);
  const ms = Number.isFinite(t.getTime()) ? t.getTime() : Date.now();
  return new Date(Math.floor(ms / 300000) * 300000).toISOString().replace(/[^0-9]/g, "").slice(0, 12);
}

function createTelemetryDetection({ event, ruleId, ruleName, severity, tactic, mitre, groups = [], fullLog, iocs = [] }) {
  const ts = event.receivedAt || event.time || new Date().toISOString();
  const agentId = String(event.agent_id || event.agentId || "unknown");
  const id = `TEL-${ruleId}-${agentId}-${telemetryWindowId(ts)}`;
  return recordDetectedAlert(buildDetectedAlert({
    id,
    ruleId: `OPXDR-${ruleId}`,
    ruleName,
    severity,
    tactic,
    mitre,
    time: ts,
    srcIp: event.honeypot?.public_source_ips?.[0] || event.honeypot?.source_ips?.[0] || event.ip || "-",
    dstIp: event.ip || "-",
    account: event.honeypot?.events?.find(e => e.username)?.username || "-",
    host: event.agent_name || event.hostname || agentId,
    agentId,
    agentIp: event.ip,
    location: "OPXDR agent telemetry",
    decoder: "opxdr-siem-agent",
    groups,
    iocs,
    fullLog,
    raw: { telemetry: event },
  }));
}

function evaluateSiemTelemetryDetections(event = {}) {
  const detections = [];
  const agentId = String(event.agent_id || event.agentId || "");
  const hp = event.honeypot || {};
  const hpEvents = Number(hp.event_count || 0);
  const hpSrcIps = Number(hp.source_ip_count || 0);
  const hpPublicSrcIps = Number(hp.public_source_ip_count || 0);
  const hpAuthFailures = Number(hp.auth_failures || 0);
  const commands = Array.isArray(hp.commands) ? hp.commands.filter(Boolean) : [];
  const hpEventRows = Array.isArray(hp.events) ? hp.events : [];
  const publicRows = hpEventRows.filter(row => /source_class=public|real_external=true/.test(String(row.line || "")) || row.source_class === "public");
  const realExternal = Boolean(hp.real_external || hpPublicSrcIps > 0 || publicRows.length > 0);
  const publicIocs = (hp.public_source_ips || []).slice(0, 8).map(ip => ({ t: "IP", v: ip }));
  const servicesTouched = new Set(publicRows.map(row => String(row.line || "").match(/service=([a-z0-9_-]+)/i)?.[1]).filter(Boolean));
  const eventText = hpEventRows.map(row => String(row.line || "")).join("\n").toLowerCase();
  const exploitMarker = /(\/admin|\/wp-login|\/\.env|\/etc\/passwd|jndi:|cmd=|powershell|wget|curl|busybox|chmod|base64|\.sh\b|\.elf\b)/i.test(eventText);
  const malwareRetrieval = realExternal && /(curl|wget|tftp|ftp).*https?:\/\/|https?:\/\/.*(\.sh\b|\.elf\b|payload|bot|mirai|mozi)/i.test(eventText);
  const authEvents = Array.isArray(event.auth) ? event.auth.length : 0;
  const networkEntries = Array.isArray(event.network) ? event.network : [];

  if (hpEvents > 0) {
    detections.push(createTelemetryDetection({
      event,
      ruleId: "209306",
      ruleName: "OPXDR honeypot traffic observed on cloud agent",
      severity: "MEDIUM",
      tactic: "Initial Access",
      mitre: "T1110,T1021.004",
      groups: ["opxdr_siem", "honeypot", realExternal ? "real_external" : "lab_or_synthetic", "medium"],
      iocs: (hp.source_ips || []).slice(0, 6).map(ip => ({ t: "IP", v: ip })),
      fullLog: `OPXDR_SIEM_DETECTION agent_id=${agentId} honeypot_events=${hpEvents} honeypot_src_ips=${hpSrcIps} public_src_ips=${hpPublicSrcIps} real_external=${realExternal}`,
    }));
  }

  if (realExternal) {
    detections.push(createTelemetryDetection({
      event,
      ruleId: "209309",
      ruleName: "Public internet source hit OPXDR honeypot decoy",
      severity: "MEDIUM",
      tactic: "Initial Access",
      mitre: "T1190,T1595.002",
      groups: ["opxdr_siem", "honeypot", "real_external", "medium"],
      iocs: publicIocs,
      fullLog: `OPXDR_SIEM_DETECTION agent_id=${agentId} real_external=true public_src_ips=${hpPublicSrcIps} services_touched=${servicesTouched.size || 1}`,
    }));
  }

  if (hpAuthFailures >= 5 || hpSrcIps >= 3 || (realExternal && (servicesTouched.size >= 2 || exploitMarker))) {
    detections.push(createTelemetryDetection({
      event,
      ruleId: "209307",
      ruleName: realExternal ? "Correlated public honeypot behavior indicates active probing" : "Honeypot authentication failure burst or source diversity",
      severity: "HIGH",
      tactic: "Credential Access",
      mitre: "T1110,T1021.004",
      groups: ["opxdr_siem", "honeypot", realExternal ? "real_external" : "credential_access", "high"],
      iocs: publicIocs.length ? publicIocs : (hp.source_ips || []).slice(0, 8).map(ip => ({ t: "IP", v: ip })),
      fullLog: `OPXDR_SIEM_DETECTION agent_id=${agentId} real_external=${realExternal} auth_failures=${hpAuthFailures} source_ip_count=${hpSrcIps} public_src_ips=${hpPublicSrcIps} services_touched=${servicesTouched.size} exploit_marker=${exploitMarker}`,
    }));
  }

  if (malwareRetrieval) {
    detections.push(createTelemetryDetection({
      event,
      ruleId: "209310",
      ruleName: "Critical isolated honeypot malware retrieval attempt",
      severity: "CRITICAL",
      tactic: "Command and Control",
      mitre: "T1105,T1059",
      groups: ["opxdr_siem", "honeypot", "real_external", "malware_retrieval", "critical"],
      iocs: publicIocs,
      fullLog: `OPXDR_SIEM_DETECTION agent_id=${agentId} real_external=true malware_retrieval_attempt=true contained_session=true`,
    }));
  }

  if (commands.length > 0) {
    detections.push(createTelemetryDetection({
      event,
      ruleId: "209308",
      ruleName: "Honeypot captured interactive command activity",
      severity: "HIGH",
      tactic: "Execution",
      mitre: "T1059,T1021.004",
      groups: ["opxdr_siem", "honeypot", "execution", "high"],
      iocs: commands.slice(0, 6).map(cmd => ({ t: "CMD", v: cmd })),
      fullLog: `OPXDR_SIEM_DETECTION agent_id=${agentId} honeypot_commands=${commands.length}`,
    }));
  }

  if (authEvents >= 20) {
    detections.push(createTelemetryDetection({
      event,
      ruleId: "209303",
      ruleName: "OPXDR SIEM agent authentication telemetry burst",
      severity: "MEDIUM",
      tactic: "Credential Access",
      mitre: "T1110",
      groups: ["opxdr_siem", "auth", "medium"],
      fullLog: `OPXDR_SIEM_DETECTION agent_id=${agentId} auth_events=${authEvents}`,
    }));
  }

  if (networkEntries.length >= 25) {
    detections.push(createTelemetryDetection({
      event,
      ruleId: "209441",
      ruleName: "Contextual network service diversity observed by OPXDR agent",
      severity: "MEDIUM",
      tactic: "Discovery",
      mitre: "T1049,T1046",
      groups: ["opxdr_siem", "network", "flow", "medium"],
      fullLog: `OPXDR_SIEM_DETECTION agent_id=${agentId} listeners=${networkEntries.length}`,
    }));
  }

  return detections.filter(Boolean);
}

function siemCategory(alert) {
  const groups = Array.isArray(alert.groups) ? alert.groups.filter(Boolean) : [];
  const tactic = String(alert.tactic || "").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "");
  return [...new Set([...groups, tactic, "opxdr"].filter(Boolean))].join(",");
}

function normalizedSiemEvent(alert) {
  return {
    event: { kind: "alert", category: siemCategory(alert), type: "opxdr_testfire", action: alert.injected ? "testfire" : "detect", severity: alert.severity },
    rule: { id: alert.ruleId, name: alert.ruleName, level: alert.level, mitre: alert.mitre, groups: alert.groups || [] },
    host: { name: alert.host || "soc-admin", ip: alert.agentIp || undefined },
    source: { ip: alert.srcIp && alert.srcIp !== "-" ? alert.srcIp : undefined, user: alert.account && alert.account !== "-" ? alert.account : undefined },
    destination: { ip: alert.dstIp && alert.dstIp !== "-" ? alert.dstIp : undefined },
    opxdr: { id: alert.id, location: alert.location, decoder: alert.decoder, iocs: alert.iocs || [], testfire: !!alert.raw?.testfire || !!alert.injected },
    message: alert.fullLog || alert.ruleName,
    timestamp: alert.time || new Date().toISOString(),
    raw: alert.raw || alert,
  };
}

const sevToNum = (sev) => ({ LOW: 3, MEDIUM: 5, HIGH: 8, CRITICAL: 10 }[String(sev || "").toUpperCase()] || 5);
const escCef = (v = "") => String(v).replace(/\\/g, "\\\\").replace(/=/g, "\\=").replace(/\n/g, " ").replace(/\r/g, " ");

function toCef(alert) {
  const n = normalizedSiemEvent(alert);
  return `CEF:0|OPXDR|OPXDR Server|2.0|${escCef(alert.ruleId)}|${escCef(alert.ruleName)}|${sevToNum(alert.severity)}|cat=${escCef(n.event.category)} act=testfire rt=${Date.parse(alert.time || new Date())} shost=${escCef(alert.host)} src=${escCef(alert.srcIp)} dst=${escCef(alert.dstIp)} suser=${escCef(alert.account)} cs1Label=mitre cs1=${escCef(alert.mitre)} cs2Label=location cs2=${escCef(alert.location)} msg=${escCef(alert.fullLog || alert.ruleName)}`;
}

function toLeef(alert) {
  const n = normalizedSiemEvent(alert);
  return `LEEF:2.0|OPXDR|OPXDR Server|2.0|${alert.ruleId}|cat=${n.event.category}\tsev=${alert.severity}\tdevTime=${alert.time}\tsrc=${alert.srcIp}\tdst=${alert.dstIp}\tusrName=${alert.account}\thostname=${alert.host}\trule=${alert.ruleName}\tmitre=${alert.mitre}\tmsg=${String(alert.fullLog || alert.ruleName).replace(/\t/g, " ")}`;
}

function syslogPayload(alert) {
  if (SIEM_SYSLOG_FORMAT === "json") return JSON.stringify(normalizedSiemEvent(alert));
  if (SIEM_SYSLOG_FORMAT === "leef") return toLeef(alert);
  return toCef(alert);
}

function sendSyslog(alert) {
  if (!SIEM_SYSLOG_HOST) return Promise.resolve({ skipped: "syslog" });
  const payload = `<134>${new Date().toISOString()} ${alert.host || "opxdr"} OPXDR ${process.pid} - - ${syslogPayload(alert)}`;
  if (SIEM_SYSLOG_PROTO === "tcp") {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ host: SIEM_SYSLOG_HOST, port: SIEM_SYSLOG_PORT }, () => {
        socket.end(payload + "\n");
        resolve({ ok: true, sink: "syslog-tcp" });
      });
      socket.on("error", reject);
      socket.setTimeout(5000, () => { socket.destroy(); reject(new Error("syslog tcp timeout")); });
    });
  }
  return new Promise((resolve, reject) => {
    const client = dgram.createSocket("udp4");
    client.send(Buffer.from(payload), SIEM_SYSLOG_PORT, SIEM_SYSLOG_HOST, (err) => {
      client.close();
      err ? reject(err) : resolve({ ok: true, sink: "syslog-udp" });
    });
  });
}

async function postJson(url, body, headers = {}) {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body), agent: insecureAgent });
  if (!r.ok) throw new Error(`${url} -> ${r.status}: ${(await r.text()).slice(0, 300)}`);
  return { ok: true };
}

async function sendSplunk(alert) {
  if (!SPLUNK_HEC_URL || !SPLUNK_HEC_TOKEN) return { skipped: "splunk" };
  return postJson(SPLUNK_HEC_URL, { time: Date.parse(alert.time || new Date()) / 1000, host: alert.host, source: "opxdr:testfire", sourcetype: "opxdr:alert", index: SPLUNK_HEC_INDEX, event: normalizedSiemEvent(alert) }, { Authorization: `Splunk ${SPLUNK_HEC_TOKEN}` });
}

async function sendElastic(alert) {
  if (!ELASTIC_INGEST_URL) return { skipped: "elastic" };
  const headers = {};
  if (ELASTIC_API_KEY) headers.Authorization = `ApiKey ${ELASTIC_API_KEY}`;
  else if (ELASTIC_USERNAME || ELASTIC_PASSWORD) headers.Authorization = `Basic ${Buffer.from(`${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}`).toString("base64")}`;
  return postJson(ELASTIC_INGEST_URL, normalizedSiemEvent(alert), headers);
}

function sentinelSignature(date, contentLength, method, contentType, resource) {
  const xHeaders = `x-ms-date:${date}`;
  const stringToHash = `${method}\n${contentLength}\n${contentType}\n${xHeaders}\n${resource}`;
  const decodedKey = Buffer.from(SENTINEL_SHARED_KEY, "base64");
  const encodedHash = crypto.createHmac("sha256", decodedKey).update(stringToHash, "utf8").digest("base64");
  return `SharedKey ${SENTINEL_WORKSPACE_ID}:${encodedHash}`;
}

async function sendSentinel(alert) {
  if (!SENTINEL_WORKSPACE_ID || !SENTINEL_SHARED_KEY) return { skipped: "sentinel" };
  const body = JSON.stringify([normalizedSiemEvent(alert)]);
  const date = new Date().toUTCString();
  const resource = "/api/logs";
  const url = `https://${SENTINEL_WORKSPACE_ID}.ods.opinsights.azure.com${resource}?api-version=2016-04-01`;
  const headers = { "Content-Type": "application/json", "Log-Type": SENTINEL_LOG_TYPE, "x-ms-date": date, Authorization: sentinelSignature(date, Buffer.byteLength(body), "POST", "application/json", resource) };
  const r = await fetch(url, { method: "POST", headers, body, agent: insecureAgent });
  if (!r.ok) throw new Error(`Sentinel -> ${r.status}: ${(await r.text()).slice(0, 300)}`);
  return { ok: true };
}

async function sendQradar(alert) {
  if (!QRADAR_INGEST_URL) return { skipped: "qradar" };
  const headers = QRADAR_TOKEN ? { SEC: QRADAR_TOKEN } : {};
  const r = await fetch(QRADAR_INGEST_URL, { method: "POST", headers: { "Content-Type": "text/plain", ...headers }, body: toLeef(alert), agent: insecureAgent });
  if (!r.ok) throw new Error(`QRadar -> ${r.status}: ${(await r.text()).slice(0, 300)}`);
  return { ok: true };
}

async function sendChronicle(alert) {
  if (!CHRONICLE_INGEST_URL || !CHRONICLE_TOKEN) return { skipped: "chronicle" };
  return postJson(CHRONICLE_INGEST_URL, normalizedSiemEvent(alert), { Authorization: `Bearer ${CHRONICLE_TOKEN}` });
}

async function forwardAlertToSiems(alert) {
  if (!SIEM_FORWARD_ENABLED) return;
  const sinks = [sendSyslog, sendSplunk, sendElastic, sendSentinel, sendQradar, sendChronicle];
  const results = await Promise.allSettled(sinks.map((fn) => fn(alert)));
  for (const r of results) {
    if (r.status === "rejected") console.warn("[siem-forward]", r.reason.message);
  }
}

function splitArgs(value) {
  return String(value || "")
    .match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g)?.map((s) => s.replace(/^['"]|['"]$/g, "")) || [];
}

function expandTestfireArgs(template, rule) {
  const repl = {
    ruleId: rule.wazuhRuleId || rule.id || "",
    id: rule.id || rule.wazuhRuleId || "",
    name: rule.name || "",
    severity: rule.severity || "HIGH",
    tactic: rule.tactic || "-",
    mitre: rule.mitre || "-",
    file: rule.file || "",
    filePath: rule.filePath || "",
  };
  return splitArgs(template || "{ruleId}").map((arg) =>
    arg.replace(/\{(ruleId|id|name|severity|tactic|mitre|file|filePath)\}/g, (_, k) => repl[k])
  );
}

function defaultTestfireCommand(rule) {
  const command = process.env.TESTFIRE_COMMAND || path.join(__dirname, "..", "scripts", "testfire");
  const args = expandTestfireArgs(process.env.TESTFIRE_ARGS || "{ruleId} --wazuh --inject", rule);
  return { command, args, env: { OPXDR_TESTFIRE_RULE: JSON.stringify(rule) } };
}

function resolveTestfireRule(id, bodyRule = {}, allRules = []) {
  return allRules.find((r) => r.id === id || r.wazuhRuleId === id) || {
    ...bodyRule,
    id: bodyRule.id || id,
    wazuhRuleId: bodyRule.wazuhRuleId || id,
  };
}

function runTestfireCommand(rule, override = {}) {
  const defaults = defaultTestfireCommand(rule);
  const defaultCommand = path.resolve(defaults.command);
  const requestedCommand = override.command ? path.resolve(String(override.command)) : defaultCommand;
  const allowCommandOverride = process.env.ALLOW_TESTFIRE_COMMAND_OVERRIDE === "true";
  if (requestedCommand !== defaultCommand && !allowCommandOverride) {
    throw new Error("Command override disabled. Set ALLOW_TESTFIRE_COMMAND_OVERRIDE=true to allow custom binaries.");
  }
  const args = Array.isArray(override.args) ? override.args.map(String) : defaults.args;
  const envRule = override.rule ? JSON.stringify(override.rule) : defaults.env.OPXDR_TESTFIRE_RULE;
  const env = { ...process.env, OPXDR_TESTFIRE_RULE: envRule };
  return new Promise((resolve, reject) => {
    const child = spawn(requestedCommand, args, { env });
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (d) => { stdout += d.toString(); });
    child.stderr?.on("data", (d) => { stderr += d.toString(); });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolve({ command: requestedCommand, args, stdout: stdout.slice(0, 4000), stderr: stderr.slice(0, 4000) });
      else reject(new Error(`${command} exited ${code}: ${(stderr || stdout).slice(0, 500)}`));
    });
  });
}

app.get("/api/rules/:id/testfire", async (req, res) => {
  const all = (await loadLocalRules()).concat(await loadWazuhApiRules());
  const rule = resolveTestfireRule(req.params.id, {}, all);
  const command = defaultTestfireCommand(rule);
  res.json({ ok: true, rule, command: { command: command.command, args: command.args }, rulePayload: JSON.parse(command.env.OPXDR_TESTFIRE_RULE) });
});

app.post("/api/rules/:id/testfire", async (req, res) => {
  const bodyRule = req.body?.rule || {};
  const editedRule = req.body?.rulePayload || req.body?.editedRule || null;
  const all = (await loadLocalRules()).concat(await loadWazuhApiRules());
  const rule = editedRule || resolveTestfireRule(req.params.id, bodyRule, all);

  let commandResult = null;
  let commandError = null;
  try {
    commandResult = await runTestfireCommand(rule, { command: req.body?.command, args: req.body?.args, rule: editedRule });
  } catch (e) {
    commandError = e.message;
  }

  if (commandResult && process.env.TESTFIRE_INJECT_AFTER_COMMAND !== "true") {
    return res.json({ ok: true, mode: "command", ruleId: rule.wazuhRuleId || rule.id, command: commandResult });
  }

  const alert = createInjectedAlert({
    ruleId: rule.wazuhRuleId || rule.id,
    ruleName: rule.name || `Testfire ${rule.id || req.params.id}`,
    severity: rule.severity || "HIGH",
    level: rule.level,
    tactic: rule.tactic,
    mitre: rule.mitre,
    host: "soc-admin",
    agentId: "000",
    location: "OPXDR Detection Registry",
    decoder: "opxdr-testfire",
    groups: Array.isArray(rule.groups) ? rule.groups : [rule.group || "testfire"].filter(Boolean),
    iocs: [{ t: "RuleID", v: String(rule.wazuhRuleId || rule.id || req.params.id) }],
    fullLog: `OPXDR testfire for rule ${rule.wazuhRuleId || rule.id || req.params.id}: ${rule.name || "Unnamed rule"}`,
    testfire: true,
    command: commandResult,
    commandError,
  });

  res.json({ ok: true, mode: commandResult ? "command+inject" : "simulated", ruleId: rule.wazuhRuleId || rule.id, command: commandResult, commandError, alert });
});

app.post("/api/alerts/inject", (req, res) => {
  const b = req.body || {};
  if (!b.ruleName && !b.ruleId) return res.status(400).json({ error: "ruleName or ruleId required" });
  const alert = createInjectedAlert(b);
  res.json({ ok: true, id: alert.id, alert });
});

// ─── Persistent high/critical alert store ─────────────────────────────────
app.get("/api/alerts/persisted", (req, res) => {
  const limit = parseInt(req.query.limit || "10000", 10);
  const sliced = persistedAlerts.slice(-limit).reverse();
  res.json({ alerts: sliced, count: sliced.length, total: persistedAlerts.length });
});

// ─── AI provider helpers (shared by /api/claude proxy + auto-report) ─────
// Prefers OpenCode Zen (https://opencode.ai/zen/v1/messages). Falls back to direct
// Anthropic API only when ANTHROPIC_API_KEY is explicitly set.
function aiProvider() {
  const oczKey = process.env.OCZ_API_KEY || process.env.OPENCODE_API_KEY;
  const antKey = process.env.ANTHROPIC_API_KEY;
  if (!oczKey && !antKey) return null;
  // Prefer direct Anthropic only if explicitly set, otherwise use Zen
  if (antKey && !oczKey) {
    return {
      kind: "anthropic",
      apiKey: antKey,
      apiUrl: process.env.ANTHROPIC_API_URL || "https://api.anthropic.com/v1/messages",
      model:  process.env.ANTHROPIC_MODEL   || "claude-sonnet-4-6",
    };
  }
  const base = (process.env.OCZ_BASE_URL || process.env.OPENCODE_API_URL || "https://opencode.ai/zen/v1")
    .replace(/\/messages\/?$/, "")
    .replace(/\/+$/, "");
  return {
    kind: "zen",
    apiKey: oczKey,
    apiUrl: `${base}/messages`,
    model:  process.env.OPENCODE_MODEL || "claude-sonnet-4-6",
  };
}

function aiHeaders(p) {
  return {
    "Content-Type": "application/json",
    "x-api-key": p.apiKey,
    "Authorization": `Bearer ${p.apiKey}`,
    "anthropic-version": "2023-06-01",
  };
}

// Non-streaming AI call via Zen. Returns the assembled text or throws.
async function callAi({ system, messages, max_tokens = 1200 }) {
  const key = process.env.OCZ_API_KEY || process.env.OPENCODE_API_KEY;
  if (!key) throw new Error("No AI key configured — set OCZ_API_KEY or OPENCODE_API_KEY in .env");
  const base = (process.env.OCZ_BASE_URL || "https://opencode.ai/zen/v1").replace(/\/+$/, "");
  const models = ["nemotron-3-ultra-free", "deepseek-v4-flash-free", "minimax-m3-free"];
  const msgs = system ? [{ role: "system", content: system }, ...messages] : messages;
  let lastErr;
  for (const model of models) {
    try {
      const resp = await fetch(`${base}/chat/completions`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${key}` },
        body: JSON.stringify({ model, messages: msgs, max_tokens }),
      });
      if (!resp.ok) {
        lastErr = new Error(`${model} returned ${resp.status}`);
        const text = await resp.text().catch(() => "");
        if (text) lastErr.message += `: ${text.slice(0, 200)}`;
        continue;
      }
      const j = await resp.json();
      const text = j?.choices?.[0]?.message?.content;
      if (text) return text;
      lastErr = new Error(`${model} returned empty response`);
    } catch (e) {
      lastErr = e;
      console.warn(`[callAi] ${model} failed:`, e.message);
    }
  }
  throw lastErr || new Error("All AI models exhausted");
}

// ─── AI proxy (OpenCode / Anthropic) ──────────────────────────────────────
app.post("/api/claude", async (req, res) => {
  const { system, messages, max_tokens = 1200, stream = true } = req.body || {};
  if (!Array.isArray(messages)) return res.status(400).json({ error: "messages[] required" });

  const p = aiProvider();
  if (!p) return res.status(503).json({ error: "No AI key configured. Set OPENCODE_API_KEY or ANTHROPIC_API_KEY in .env" });

  try {
    const upstream = await fetch(p.apiUrl, {
      method: "POST",
      headers: aiHeaders(p),
      body: JSON.stringify({ model: p.model, max_tokens, system, messages, stream }),
    });
    if (!upstream.ok) {
      const t = await upstream.text();
      return res.status(upstream.status).json({ error: t });
    }
    if (!stream) {
      const j = await upstream.json();
      return res.json(j);
    }
    res.set({
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    });
    upstream.body.on("data", (chunk) => res.write(chunk));
    upstream.body.on("end", () => res.end());
    upstream.body.on("error", (e) => { console.error(e); res.end(); });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});



// Send text as simulated OpenAI-format SSE stream and close (used by non-streaming callers)
function sseText(res, text) {
  res.set({ "Content-Type":"text/event-stream","Cache-Control":"no-cache",Connection:"keep-alive","X-Accel-Buffering":"no" });
  const words = text.split(/(?<=\s)/);
  for (const w of words) {
    if (w) res.write(`data: ${JSON.stringify({ choices:[{ delta:{ content:w } }] })}\n\n`);
  }
  res.write("data: [DONE]\n\n");
  res.end();
}

// Stream OpenCode events for sessionId → forward text deltas to expressRes as SSE.
// Returns a Promise that resolves when session goes idle, stream ends, or timeout.
function streamOpenCodeEvents(evtRes, sessionId, expressRes) {
  return new Promise((resolve) => {
    let buf = "";
    let done = false;
    let hasOutput = false;
    const partTypes = new Map(); // partID -> "text" | "reasoning" | "step-start" | ...

    const finish = (reason) => {
      if (done) return;
      done = true;
      console.log(`[agent stream ${sessionId.slice(-8)}] done (${reason}) hasOutput=${hasOutput}`);
      try { evtRes.body.destroy(); } catch {}
      if (hasOutput) {
        expressRes.write("data: [DONE]\n\n");
        expressRes.end();
      }
      // If !hasOutput, caller decides: fallback or error — do NOT end the response here
      resolve(hasOutput);
    };

    const timeout = setTimeout(() => finish("timeout"), 180_000);

    evtRes.body.on("data", (chunk) => {
      buf += chunk.toString();
      const lines = buf.split("\n");
      buf = lines.pop() || "";

      for (const line of lines) {
        if (!line.startsWith("data:")) continue;
        const raw = line.slice(5).trim();
        if (!raw) continue;
        try {
          const evt = JSON.parse(raw);
          const p = evt.payload;
          if (!p) continue;
          const props = p.properties || {};

          if (p.type === "message.part.updated") {
            // Track part types across ALL sessions — OpenCode spawns subagents with different
            // session IDs for complex tasks; their events share the global event stream.
            const part = props.part || {};
            if (part.id && part.type) partTypes.set(part.id, part.type);
          } else if (p.type === "message.part.delta" && props.field === "text" && props.delta) {
            // Forward text deltas from ANY session (subagents do the actual analysis work).
            // Filter only internal step/reasoning parts which are not useful to show.
            const pt = partTypes.get(props.partID);
            if (pt !== "reasoning" && pt !== "step-start" && pt !== "step-finish") {
              hasOutput = true;
              expressRes.write(`data: ${JSON.stringify({ choices:[{ delta:{ content:props.delta } }] })}\n\n`);
            }
          } else if (p.type === "session.idle" && props.sessionID === sessionId) {
            // Only our main session going idle signals that the full investigation is complete
            clearTimeout(timeout);
            finish("idle");
          }
        } catch {}
      }
    });

    evtRes.body.on("error", (e) => { console.error("[agent stream]", e.message); clearTimeout(timeout); finish("error"); });
    evtRes.body.on("end",   ()    => { clearTimeout(timeout); finish("stream-end"); });
  });
}

// ─── Agent model routing ──────────────────────────────────────────────────────
// Each agent type is mapped to a primary + fallback chain of models. Models are routed by family:
//   - claude-* → /v1/messages (Anthropic SSE format)
//   - everything else (gpt-*, gemini-*, nemotron-*, minimax-*, etc.) → /v1/chat/completions (OpenAI SSE)
// All run through OpenCode Zen at https://opencode.ai/zen/v1
// See: https://opencode.ai/docs/zen/
//
// Strategy: USE FREE MODELS FIRST. The workspace is at its $20 Sonnet spending cap, so the
// primary choice for every agent is one of OpenCode Zen's beta-free models (zero $ cost).
// Claude Haiku is added as a secondary fallback for the validation agent only (small, cheap).
//
// Free model strengths:
//   - nemotron-3-ultra-free (NVIDIA Nemotron 3 Ultra 120B): excellent reasoning, large context
//                                                           → investigate, slackReport, irPlaybook, ruleAssistant
//   - deepseek-v4-flash-free (DeepSeek V4 Flash):           fast reasoning, good all-rounder
//                                                           → logAnalysis, validate
//   - minimax-m3-free (MiniMax M3, 460B MoE):               strong instruction following, fast
//                                                           → logAnalysis, validate
//   - qwen3.6-plus-free (Qwen 3.6 Plus):                    backup
//   - big-pickle (DeepSeek-V4 Flash stealth):               backup, very fast
const AGENT_CFG = {
  investigate:   { models: ["nemotron-3-ultra-free", "deepseek-v4-flash-free", "minimax-m3-free"],     tokens: 4096 },
  logAnalysis:   { models: ["minimax-m3-free",       "qwen3.6-plus-free",      "big-pickle"],          tokens: 2048 },
  slackReport:   { models: ["nemotron-3-ultra-free", "deepseek-v4-flash-free", "minimax-m3-free"],     tokens: 4096 },
  ruleAssistant: { models: ["nemotron-3-ultra-free", "deepseek-v4-flash-free", "minimax-m3-free"],     tokens: 3000 },
  irPlaybook:    { models: ["nemotron-3-ultra-free", "deepseek-v4-flash-free", "minimax-m3-free"],     tokens: 6000 },
  validate:      { models: ["nemotron-3-ultra-free", "deepseek-v4-flash-free", "claude-haiku-4-5"],    tokens: 4096 },
};

// Errors that should trigger fallback to the next model
function shouldFallbackOnError(errMsg) {
  const m = (errMsg || "").toLowerCase();
  return m.includes("userlimiterror")
      || m.includes("monthly spending limit")
      || m.includes("rate_limit")
      || m.includes("rate limit")
      || m.includes("not_found")
      || m.includes("not found")
      || m.includes("model_not_found")
      || m.includes("invalid_request_error")
      || m.includes("overloaded")
      || m.includes("503")
      || m.includes("502")
      || m.includes("timeout")
      || m.includes("abort")
      || m.includes("etimedout")
      || m.includes("econnrefused")
      || m.includes("econnreset")
      || m.includes("network")
      || m.includes("fetch failed");
}

// Detect which API surface a model needs based on its ID
function modelEndpointKind(model) {
  if (/^claude-/i.test(model)) return "messages";          // Anthropic-compatible
  if (/^gpt-/i.test(model))     return "responses";        // OpenAI Responses API
  if (/^gemini-/i.test(model))  return "google";           // Google AI SDK
  return "chat";                                           // OpenAI chat/completions
}

// Pull the OpenCode Zen API key + base URL with safe defaults.
// Both OCZ_API_KEY and OPENCODE_API_KEY are accepted (same key, different env names).
function zenConfig() {
  const key  = process.env.OCZ_API_KEY || process.env.OPENCODE_API_KEY || "";
  const base = (process.env.OCZ_BASE_URL || "https://opencode.ai/zen/v1").replace(/\/+$/, "");
  return { key, base };
}

// Stream a Zen /v1/messages call (Claude models, Anthropic SSE format).
// Pipes upstream SSE bytes directly to the client — frontend handles content_block_delta.
// Throws BEFORE writing to res if upstream returns a non-2xx (so caller can try next model).
async function streamZenMessages({ model, system, messages, maxTok, key, base, res }) {
  const url = `${base}/messages`;
  const upstream = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": key,
      "Authorization": `Bearer ${key}`,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model,
      max_tokens: maxTok,
      system: system || undefined,
      messages,
      stream: true,
    }),
  });
  if (!upstream.ok) {
    const body = await upstream.text();
    throw new Error(`Zen messages ${upstream.status}: ${body.slice(0, 300)}`);
  }
  let gotContent = false;
  let buf = "";
  await new Promise((resolve, reject) => {
    upstream.body.on("data", c => {
      buf += c.toString();
      const lines = buf.split("\n");
      buf = lines.pop() || "";
      for (const ln of lines) {
        if (!ln.startsWith("data:")) continue;
        const d = ln.slice(5).trim();
        if (!d) continue;
        try {
          const evt = JSON.parse(d);
          if (evt.type === "content_block_delta" && evt.delta?.text) {
            gotContent = true;
          }
        } catch {}
        try { res.write(ln + "\n"); } catch {}
      }
    });
    upstream.body.on("end", () => {
      if (buf) try { res.write(buf); } catch {}
      if (gotContent) {
        try { res.end(); } catch {}
        resolve();
      } else {
        reject(new Error("Empty response from model (no text content blocks)"));
      }
    });
    upstream.body.on("error", e => {
      console.error("[zen messages stream]", e.message);
      if (gotContent) {
        try { res.end(); } catch {}
        resolve();
      } else {
        reject(e);
      }
    });
  });
}

// Stream a Zen /v1/chat/completions call (non-Claude models, OpenAI SSE format).
// Strips reasoning/reasoning_details from delta chunks (they bloat bandwidth and the
// frontend ignores them anyway) and drops trailing cost-summary frames after [DONE].
// Throws BEFORE writing to res if upstream returns a non-2xx (so caller can try next model).
async function streamZenChat({ model, system, messages, maxTok, key, base, res }) {
  const url = `${base}/chat/completions`;
  const oMsgs = system ? [{ role: "system", content: system }, ...messages] : messages;
  const upstream = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${key}`,
    },
    body: JSON.stringify({
      model,
      messages: oMsgs,
      stream: true,
      max_tokens: maxTok,
    }),
  });
  if (!upstream.ok) {
    const body = await upstream.text();
    throw new Error(`Zen chat ${upstream.status}: ${body.slice(0, 300)}`);
  }

  let buf = "";
  let doneSent = false;
  let gotFirstToken = false;
  let gotContent = false;
  const firstTokenTimeout = setTimeout(() => {
    if (!gotFirstToken) {
      console.warn(`[zen chat] ${model}: no first token after 120s — aborting`);
      upstream.body.destroy(new Error("first-token-timeout"));
    }
  }, 120_000);
  const handleLine = (line) => {
    if (!line.startsWith("data:")) return;
    const d = line.slice(5).trim();
    if (!d) return;
    if (d === "[DONE]") {
      if (!doneSent) { res.write("data: [DONE]\n\n"); doneSent = true; }
      return;
    }
    try {
      const j = JSON.parse(d);
      if (!Array.isArray(j.choices) || j.choices.length === 0) return;
      const cleanChoices = j.choices.map(ch => {
        if (!ch || !ch.delta) return ch;
        const { reasoning, reasoning_details, ...keep } = ch.delta;
        return { ...ch, delta: keep };
      });
      const hasContent = cleanChoices.some(ch =>
        (ch.delta?.content && ch.delta.content.length > 0) ||
        ch.delta?.role ||
        ch.finish_reason
      );
      if (!hasContent) return;
      gotContent = gotContent || cleanChoices.some(ch =>
        ch.delta?.content && ch.delta.content.length > 0
      );
      try { res.write(`data: ${JSON.stringify({ ...j, choices: cleanChoices })}\n\n`); } catch {}
    } catch {}
  };

  await new Promise((resolve, reject) => {
    upstream.body.on("data", (chunk) => {
      buf += chunk.toString();
      const lines = buf.split("\n");
      buf = lines.pop() || "";
      for (const line of lines) {
        if (!gotFirstToken && line.startsWith("data:") && line.slice(5).trim() && !line.includes('"content":""')) {
          gotFirstToken = true;
          clearTimeout(firstTokenTimeout);
        }
        handleLine(line);
      }
    });
    upstream.body.on("end", () => {
      if (buf) handleLine(buf);
      if (gotContent) {
        if (!doneSent) { try { res.write("data: [DONE]\n\n"); } catch {} }
        try { res.end(); } catch {}
        resolve();
      } else {
        reject(new Error("Empty response from model (no text content)"));
      }
    });
    upstream.body.on("error", (e) => {
      clearTimeout(firstTokenTimeout);
      console.error("[zen chat stream]", e.message);
      if (gotContent) {
        try { res.end(); } catch {}
        resolve();
      } else {
        reject(e);
      }
    });
  });
}

// Direct Anthropic API path (used only when ANTHROPIC_API_KEY is set explicitly,
// for users who want to bypass OpenCode Zen and bill against Anthropic directly).
async function streamAnthropicDirect({ model, system, messages, maxTok, key, res }) {
  const url = process.env.ANTHROPIC_API_URL || "https://api.anthropic.com/v1/messages";
  const upstream = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": key,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model,
      max_tokens: maxTok,
      system: system || undefined,
      messages,
      stream: true,
    }),
  });
  if (!upstream.ok) {
    const body = await upstream.text();
    throw new Error(`Anthropic ${upstream.status}: ${body.slice(0, 300)}`);
  }
  let gotContent = false;
  let buf = "";
  await new Promise((resolve, reject) => {
    upstream.body.on("data", c => {
      buf += c.toString();
      const lines = buf.split("\n");
      buf = lines.pop() || "";
      for (const ln of lines) {
        if (!ln.startsWith("data:")) continue;
        const d = ln.slice(5).trim();
        if (!d) continue;
        try {
          const evt = JSON.parse(d);
          if (evt.type === "content_block_delta" && evt.delta?.text) {
            gotContent = true;
          }
        } catch {}
        try { res.write(ln + "\n"); } catch {}
      }
    });
    upstream.body.on("end", () => {
      if (buf) try { res.write(buf); } catch {}
      if (gotContent) {
        try { res.end(); } catch {}
        resolve();
      } else {
        reject(new Error("Empty response from Anthropic (no text content blocks)"));
      }
    });
    upstream.body.on("error", e => {
      console.error("[anthropic direct]", e.message);
      if (gotContent) {
        try { res.end(); } catch {}
        resolve();
      } else {
        reject(e);
      }
    });
  });
}

// Main agent dispatcher. Walks the model fallback chain for an agent type:
//   1. Try ANTHROPIC_API_KEY direct path if a Claude model is in the chain
//   2. For each model in cfg.models: try OpenCode Zen until one succeeds
// Once any upstream starts streaming bytes to res, we commit to that response.
async function callAgentFallback(agentType, messages, res) {
  const cfg     = AGENT_CFG[agentType] || AGENT_CFG.investigate;
  const models  = Array.isArray(cfg.models) ? cfg.models : [cfg.model || "claude-haiku-4-5"];
  const maxTok  = cfg.tokens || 4096;

  // Separate system prompt from conversation
  let system = "";
  const chatMsgs = [];
  for (const m of messages) {
    if (m.role === "system") system += (system ? "\n" : "") + m.content;
    else chatMsgs.push(m);
  }

  const { key, base } = zenConfig();
  const antKey        = process.env.ANTHROPIC_API_KEY;

  if (!key && !antKey) {
    throw new Error("No AI key configured — set OCZ_API_KEY (or OPENCODE_API_KEY or ANTHROPIC_API_KEY) in .env");
  }

  const errors = [];
  for (let i = 0; i < models.length; i++) {
    const model = models[i];
    const kind  = modelEndpointKind(model);
    try {
      // Direct Anthropic API path (only if explicitly set + model is Claude family)
      if (antKey && kind === "messages" && i === 0) {
        console.log(`[agent ${agentType}] try ${i+1}/${models.length} → Anthropic direct: ${model}`);
        await streamAnthropicDirect({ model, system, messages: chatMsgs, maxTok, key: antKey, res });
        return;
      }
      // OpenCode Zen path
      if (key) {
        console.log(`[agent ${agentType}] try ${i+1}/${models.length} → Zen ${kind}: ${model}`);
        if (kind === "messages") {
          await streamZenMessages({ model, system, messages: chatMsgs, maxTok, key, base, res });
        } else {
          await streamZenChat({ model, system, messages: chatMsgs, maxTok, key, base, res });
        }
        return;
      }
      // No key for this kind — skip (e.g. Anthropic-only key with non-Claude model)
      throw new Error(`no key available for model kind=${kind}`);
    } catch (e) {
      const msg = e?.message || String(e);
      errors.push(`${model}: ${msg.slice(0, 200)}`);
      console.warn(`[agent ${agentType}] ${model} failed: ${msg.slice(0, 160)}`);
      if (i < models.length - 1) {
        continue; // try next model regardless of error type
      }
      throw new Error(`All ${models.length} model(s) failed for agent "${agentType}". Last: ${msg.slice(0, 250)}`);
    }
  }
}

// ─── Investigation persistence (shared between geo.html and OPXDR app) ──────
const INVESTIGATIONS_FILE = path.join(__dirname, "data", "investigations.json");
async function loadInvestigations() {
  try {
    const d = await fsp.readFile(INVESTIGATIONS_FILE, "utf-8");
    return JSON.parse(d);
  } catch { return []; }
}
async function saveInvestigation(item) {
  const dir = path.dirname(INVESTIGATIONS_FILE);
  await fsp.mkdir(dir, { recursive: true });
  const list = await loadInvestigations();
  list.unshift(item);
  if (list.length > 200) list.length = 200;
  await fsp.writeFile(INVESTIGATIONS_FILE, JSON.stringify(list, null, 2));
}

// GET /api/investigations — return all saved investigations
app.get("/api/investigations", async (req, res) => {
  const list = await loadInvestigations();
  res.json(list);
});

// POST /api/investigations — save a new investigation
app.post("/api/investigations", async (req, res) => {
  const { type, title, entry, agentResult, status } = req.body || {};
  if (!type || !entry) return res.status(400).json({ error: "type and entry required" });
  const item = {
    id: `GEO-${Date.now()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`,
    savedAt: new Date().toISOString(),
    type: type || "investigation",
    title: title || `GeoIntel Investigation`,
    entry,
    agentResult: agentResult || null,
    status: status || "completed",
  };
  await saveInvestigation(item);
  res.json(item);
});

// /api/agent — main entry point for all SOC agents (investigate, logAnalysis, slackReport, etc.)
app.post("/api/agent", async (req, res) => {
  const { agentType, messages } = req.body || {};
  if (!Array.isArray(messages) || !agentType) return res.status(400).json({ error: "agentType and messages[] required" });

  res.set({ "Content-Type":"text/event-stream", "Cache-Control":"no-cache", Connection:"keep-alive", "X-Accel-Buffering":"no" });
  res.flushHeaders();

  try {
    await callAgentFallback(agentType, messages, res);
  } catch (e) {
    console.error(`[agent ${agentType}]`, e.message);
    const errMsg = `[Agent error: ${e.message}]\n\nTroubleshooting:\n1. Verify OCZ_API_KEY is set in .env\n2. OCZ_BASE_URL should be https://opencode.ai/zen/v1\n3. Check key has credit at https://opencode.ai/zen/`;
    // Emit OpenAI-format SSE so frontend renders the error message as text
    res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: errMsg } }] })}\n\n`);
    res.write("data: [DONE]\n\n");
    res.end();
  }
});

// ─── Slack notifications ──────────────────────────────────────────────────
const SEV_EMOJI = { CRITICAL: ":rotating_light:", HIGH: ":warning:", MEDIUM: ":large_orange_diamond:", LOW: ":small_blue_diamond:" };

function buildSlackPayload(alert, reportText) {
  const sev = alert.severity || "HIGH";
  const emoji = SEV_EMOJI[sev] || ":warning:";
  const escaped = (s) => (s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const iocLine = (alert.iocs || []).map((i) => `• \`${escaped(i.t)}\` ${escaped(i.v)}`).join("\n") || "—";

  const blocks = [
    { type: "header", text: { type: "plain_text", text: `${emoji} ${sev} Alert: ${escaped(alert.ruleName)}` } },
    { type: "divider" },
    {
      type: "section",
      fields: [
        { type: "mrkdwn", text: `*Tactic*\n${alert.tactic || "—"}` },
        { type: "mrkdwn", text: `*MITRE*\n${alert.mitre || "—"}` },
        { type: "mrkdwn", text: `*Source IP*\n${escaped(alert.srcIp)}` },
        { type: "mrkdwn", text: `*Dest IP*\n${escaped(alert.dstIp)}` },
        { type: "mrkdwn", text: `*Account*\n${escaped(alert.account)}` },
        { type: "mrkdwn", text: `*Host*\n${escaped(alert.host)}` },
      ],
    },
    { type: "section", text: { type: "mrkdwn", text: `*IOCs*\n${iocLine}` } },
  ];

  if (reportText) {
    const trimmed = reportText.length > 3500 ? reportText.slice(0, 3500) + "\n…(truncated)" : reportText;
    blocks.push({ type: "divider" });
    blocks.push({ type: "section", text: { type: "mrkdwn", text: `*AI Agent Report*\n${trimmed}` } });
  }

  blocks.push({ type: "divider" });
  blocks.push({
    type: "context",
    elements: [
      { type: "mrkdwn", text: `:shield: *OPXDR* • \`${escaped(alert.id)}\` • ${alert.time}` },
    ],
  });

  return {
    channel: SLACK_CHANNEL,
    username: SLACK_USERNAME,
    icon_emoji: ":shield:",
    text: `${emoji} ${sev} — ${escaped(alert.ruleName)}`,
    blocks,
  };
}

async function postToSlack(alert, reportText) {
  if (!SLACK_WEBHOOK_URL) throw new Error("SLACK_WEBHOOK_URL not configured");
  const body = buildSlackPayload(alert, reportText);
  const r = await fetch(SLACK_WEBHOOK_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`Slack ${r.status}: ${await r.text()}`);
  return true;
}

// POST /api/slack/notify  body: { alert, report? }
app.post("/api/slack/notify", async (req, res) => {
  const { alert, report } = req.body || {};
  if (!alert || !alert.id) return res.status(400).json({ error: "alert object required" });
  if (!SLACK_WEBHOOK_URL) return res.status(503).json({ error: "SLACK_WEBHOOK_URL not configured in .env" });
  try { await postToSlack(alert, report || ""); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── Document share to Slack ──────────────────────────────────────────────
function slackMd(text) {
  return (text || "")
    .replace(/^#{1,6}\s+(.+)$/gm, "*$1*")
    .replace(/^---+$/gm, "")
    .trim();
}

function buildDocSlackPayload(doc) {
  const blocks = [];
  const escaped = (s) => (s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

  blocks.push({
    type: "header",
    text: { type: "plain_text", text: `📄 ${escaped(doc.title || "Untitled Document")}` },
  });
  blocks.push({ type: "divider" });

  const meta = [
    `*ID* \`${escaped(doc.id)}\``,
    `*Created* ${new Date(doc.created).toLocaleString()}`,
  ];
  if (doc.alert?.severity) {
    const em = doc.alert.severity === "CRITICAL" ? ":rotating_light:" : doc.alert.severity === "HIGH" ? ":warning:" : ":large_orange_diamond:";
    meta.push(`${em} *${doc.alert.severity}*`);
  }
  if (doc.alert?.ruleName) meta.push(`*Alert* ${escaped(doc.alert.ruleName)}`);
  const src = doc.messages ? "Agent Investigation" : doc.report ? "Geo/Intel Report" : "Document";
  meta.push(`*Source* ${src}`);
  blocks.push({ type: "section", text: { type: "mrkdwn", text: meta.join("  •  ") } });

  let content = doc.report || "";
  if (!content && doc.messages) {
    content = doc.messages
      .filter((m) => m.role === "assistant")
      .map((m) => m.content)
      .join("\n\n---\n\n");
  }
  if (content) {
    content = slackMd(content);
    blocks.push({ type: "divider" });
    const lines = content.split("\n");
    const chunks = [];
    let cur = [];
    let curLen = 0;
    for (const line of lines) {
      const l = line + "\n";
      if (curLen + l.length > 2900) { chunks.push(cur.join("")); cur = [l]; curLen = l.length; }
      else { cur.push(l); curLen += l.length; }
    }
    if (cur.length) chunks.push(cur.join(""));
    for (const chunk of chunks.slice(0, 5)) {
      blocks.push({ type: "section", text: { type: "mrkdwn", text: chunk.trim() } });
    }
    if (chunks.length > 5) {
      blocks.push({ type: "section", text: { type: "mrkdwn", text: `_…and ${chunks.length - 5} more sections — open OPXDR for the full report._` } });
    }
  } else {
    blocks.push({ type: "section", text: { type: "mrkdwn", text: "_No report content in this document._" } });
  }

  blocks.push({ type: "divider" });
  blocks.push({ type: "context", elements: [{ type: "mrkdwn", text: ":shield: *OPXDR* • Shared from Reports" }] });

  return { channel: SLACK_CHANNEL, username: SLACK_USERNAME, icon_emoji: ":shield:", blocks };
}

app.post("/api/slack/share", async (req, res) => {
  const { doc } = req.body || {};
  if (!doc || !doc.id) return res.status(400).json({ error: "doc object required" });
  if (!SLACK_WEBHOOK_URL) return res.status(503).json({ error: "SLACK_WEBHOOK_URL not configured in .env" });
  try {
    const body = buildDocSlackPayload(doc);
    const r = await fetch(SLACK_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error(`Slack ${r.status}: ${await r.text()}`);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Document persistence ─────────────────────────────────────────────────
const PERSISTED_DOCS_FILE = path.join(__dirname, "..", ".persisted-docs.json");
let persistedDocs = [];

function loadPersistedDocs() {
  try {
    if (fs.existsSync(PERSISTED_DOCS_FILE)) {
      const raw = fs.readFileSync(PERSISTED_DOCS_FILE, "utf-8");
      persistedDocs = JSON.parse(raw);
      if (!Array.isArray(persistedDocs)) persistedDocs = [];
      console.log(`[docs] loaded ${persistedDocs.length} documents from disk`);
    }
  } catch (e) {
    console.warn("[docs] could not load persisted docs:", e.message);
    persistedDocs = [];
  }
}

function savePersistedDocs() {
  try {
    fs.writeFileSync(PERSISTED_DOCS_FILE, JSON.stringify(persistedDocs, null, 2));
  } catch (e) {
    console.warn("[docs] could not save persisted docs:", e.message);
  }
}

loadPersistedDocs();

// GET /api/documents — return all persisted documents
app.get("/api/documents", (_req, res) => {
  res.json({ documents: persistedDocs, count: persistedDocs.length });
});

// POST /api/documents — replace the full document list (idempotent upsert)
app.post("/api/documents", (req, res) => {
  const { documents } = req.body || {};
  if (!Array.isArray(documents)) return res.status(400).json({ error: "documents array required" });
  persistedDocs = documents;
  savePersistedDocs();
  res.json({ ok: true, count: persistedDocs.length });
});

// GET /api/settings — what the frontend should know about
app.get("/api/settings", (_req, res) => {
  res.json({
    ai_provider: process.env.OPENCODE_API_KEY ? "opencode" : process.env.ANTHROPIC_API_KEY ? "anthropic" : "none",
    slack_enabled: !!SLACK_WEBHOOK_URL,
    slack_channel: SLACK_CHANNEL,
    ai_auto_report: AI_AUTO_REPORT,
    ai_auto_report_min_level: AI_AUTO_REPORT_MIN_LEVEL,
    ai_auto_slack_notify: AI_AUTO_SLACK_NOTIFY,
  });
});

// ─── AI auto-report system prompt (shared with frontend behavior) ────────
const AUTO_REPORT_SYS = `You are a SOC agent. An alert just fired on the Wazuh SIEM. Produce a concise structured report covering:
### IOC INVENTORY
List and classify every IOC from the alert data. Tag each: CONFIRMED, SUSPECTED, or NOISE.
### ATTACK ASSESSMENT
What is this? Is IR playbook needed? What MITRE stage is this? What happens next if untreated?
### REQUIRED ACTIONS
Bullet list: what does the analyst need to do RIGHT NOW? Be specific — commands, account names, IPs.
### FURTHER ACTIONS NEEDED
Yes/No with 1-sentence justification. If yes, state exactly what.
Keep total under 350 words.`;

function alertToUserMsg(a) {
  const iocs = (a.iocs || []).map((i) => `[${i.t}] ${i.v}`).join(", ") || "—";
  return `ALERT FIRED:
ID: ${a.id}
Rule: ${a.ruleName} (${a.ruleId})
Severity: ${a.severity} (level ${a.level || "?"})
Tactic: ${a.tactic} | MITRE: ${a.mitre}
Source IP: ${a.srcIp}
Dest IP: ${a.dstIp}
Account: ${a.account}
Host: ${a.host}
IOCs: ${iocs}`;
}

// ─── Server-side tail of alerts.json → auto AI report → Slack ────────────
// One persistent tail process for the lifetime of the server. Also exposes
// the most recent N alerts (with their generated reports) via /api/alerts/auto.
const AUTO_REPORTS = []; // { alert, report, at }
function pushAutoReport(entry) {
  AUTO_REPORTS.unshift(entry);
  if (AUTO_REPORTS.length > 100) AUTO_REPORTS.pop();
}

app.get("/api/alerts/auto", (_req, res) => {
  res.json({ count: AUTO_REPORTS.length, items: AUTO_REPORTS.slice(0, 30) });
});

let autoTail = null;
function startAutoReportTail() {
  if (autoTail) return;
  if (!fs.existsSync(WAZUH_ALERTS_LOG)) {
    console.warn(`[auto-report] alerts log not found: ${WAZUH_ALERTS_LOG} — skipping`);
    return;
  }
  if (!aiProvider()) {
    console.warn("[auto-report] no AI key configured — skipping");
    return;
  }
  console.log(`[auto-report] tailing ${WAZUH_ALERTS_LOG} (min level ${AI_AUTO_REPORT_MIN_LEVEL}, slack=${AI_AUTO_SLACK_NOTIFY && !!SLACK_WEBHOOK_URL})`);
  autoTail = spawn("tail", ["-F", "-n", "0", WAZUH_ALERTS_LOG]);
  let leftover = "";
  autoTail.stdout.on("data", async (chunk) => {
    const text = leftover + chunk.toString();
    const lines = text.split("\n");
    leftover = lines.pop() || "";
    for (const ln of lines) {
      if (!ln.trim()) continue;
      const a = parseAlertLine(ln);
      if (!a) continue;
      if ((a.level || 0) < AI_AUTO_REPORT_MIN_LEVEL) continue;
      // Run AI report + Slack notify, but never block the tail loop on failures.
      (async () => {
        let report = "";
        try {
          report = await callAi({
            system: AUTO_REPORT_SYS,
            messages: [{ role: "user", content: alertToUserMsg(a) }],
            max_tokens: 700,
          });
        } catch (e) {
          console.warn("[auto-report] AI call failed:", e.message);
          report = `_AI report unavailable: ${e.message}_`;
        }
        pushAutoReport({ alert: a, report, at: new Date().toISOString() });
        if (AI_AUTO_SLACK_NOTIFY && SLACK_WEBHOOK_URL) {
          try { await postToSlack(a, report); }
          catch (e) { console.warn("[auto-report] Slack post failed:", e.message); }
        }
      })();
    }
  });
  autoTail.stderr.on("data", (d) => console.warn("[auto-report tail]", d.toString().trim()));
  autoTail.on("close", (code) => {
    console.warn(`[auto-report] tail exited (${code}) — restarting in 5s`);
    autoTail = null;
    setTimeout(startAutoReportTail, 5000);
  });
}

// ─── Custom rule save / delete + Wazuh restart ────────────────────────────
function safeName(s) {
  return String(s || "rule").replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 80);
}


function runLocalCommand(command, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, opts);
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (d) => { stdout += d.toString(); });
    child.stderr?.on("data", (d) => { stderr += d.toString(); });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolve({ stdout, stderr });
      else reject(new Error(`${command} ${args.join(" ")} exited ${code}: ${(stderr || stdout).slice(0, 500)}`));
    });
  });
}

async function tryWriteWazuh(filename, xml) {
  const target = path.join(WAZUH_RULES_DIR, filename);
  try {
    await fsp.writeFile(target, xml, { mode: 0o640 });
    return { method: "fs", path: target };
  } catch (fsErr) {
    try {
      const tmpPath = path.join(os.tmpdir ? os.tmpdir() : "/tmp", `opxdr-${process.pid}-${Date.now()}-${filename}`);
      await fsp.writeFile(tmpPath, xml, "utf8");
      await runLocalCommand("sudo", ["-n", "install", "-m", "0640", "-o", "root", "-g", "wazuh", tmpPath, target]);
      try { await fsp.unlink(tmpPath); } catch {}
      return { method: "sudo-install", path: target };
    } catch (sudoErr) {
      try {
        const token = await wazuhAuth();
        const u = new URL(`${WAZUH_API_URL}/manager/files`);
        u.searchParams.set("path", `etc/rules/${filename}`);
        u.searchParams.set("overwrite", "true");
        const res = await fetch(u, {
          method: "PUT",
          headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/octet-stream" },
          body: xml,
          agent: insecureAgent,
        });
        if (!res.ok) throw new Error(`API write failed ${res.status}: ${await res.text()}`);
        return { method: "api", path: `etc/rules/${filename}` };
      } catch (apiErr) {
        throw new Error(`fs error: ${fsErr.message} | sudo error: ${sudoErr.message} | api error: ${apiErr.message}`);
      }
    }
  }
}

async function restartWazuh() {
  try {
    const token = await wazuhAuth();
    const res = await fetch(`${WAZUH_API_URL}/manager/restart`, {
      method: "PUT",
      headers: { Authorization: `Bearer ${token}` },
      agent: insecureAgent,
    });
    if (!res.ok) throw new Error(`restart failed ${res.status}: ${await res.text()}`);
    return { method: "api", data: await res.json() };
  } catch (apiErr) {
    await runLocalCommand("sudo", ["-n", "systemctl", "restart", "wazuh-manager"]);
    return { method: "systemctl", api_error: apiErr.message };
  }
}

// POST /api/rules/custom
// body: { ruleId, name, severity, tactic, mitre, xml, yaml, group, savePath, format }
app.post("/api/rules/custom", async (req, res) => {
  const { ruleId, name, severity = "HIGH", tactic = "Defense Evasion", mitre = "", xml, yaml, group = "custom_detection", savePath, format = "xml" } = req.body || {};
  if (!ruleId || !xml) return res.status(400).json({ error: "ruleId and xml are required" });

  const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const ext = format === "sigma" ? "yml" : format === "yara" ? "yar" : "xml";
  const fileBase = `custom_${safeName(group)}_${safeName(ruleId)}_${stamp}.${ext}`;

  // 1. Save to requested savePath if provided and accessible, else fall back to CUSTOM_RULES_DIR
  let targetDir = CUSTOM_RULES_DIR;
  if (savePath && savePath !== "__custom__") {
    try {
      await fsp.mkdir(savePath, { recursive: true });
      targetDir = savePath;
    } catch (e) {
      console.warn(`[rules/custom] savePath ${savePath} inaccessible, falling back: ${e.message}`);
    }
  }
  const customPath = path.join(targetDir, fileBase);
  await fsp.writeFile(customPath, xml, "utf8");

  // Also always mirror to CUSTOM_RULES_DIR for app tracking (unless that IS the targetDir)
  if (targetDir !== CUSTOM_RULES_DIR) {
    try { await fsp.writeFile(path.join(CUSTOM_RULES_DIR, fileBase), xml, "utf8"); } catch {}
  }

  // 2. Save IR playbook YAML alongside if provided
  let yamlPath = null;
  if (yaml) {
    yamlPath = path.join(CUSTOM_PLAYBOOKS_DIR, fileBase.replace(/\.xml$/, ".yml"));
    await fsp.writeFile(yamlPath, yaml, "utf8");
  }

  // 3. Push the XML into Wazuh's rules dir so the manager loads it
  let wazuhWrite = null;
  let wazuhErr = null;
  try { wazuhWrite = await tryWriteWazuh(fileBase, xml); }
  catch (e) { wazuhErr = e.message; }

  // 4. Restart Wazuh manager so the rule is live
  let restart = null;
  let restartErr = null;
  if (WAZUH_AUTO_RESTART && wazuhWrite) {
    try { restart = await restartWazuh(); }
    catch (e) { restartErr = e.message; }
  }

  // Invalidate rules cache so next GET sees the new rule
  rulesCache = null;

  res.json({
    ok: true,
    ruleId,
    name,
    severity,
    tactic,
    mitre,
    saved: { custom: customPath, playbook: yamlPath },
    wazuh: wazuhWrite,
    wazuh_error: wazuhErr,
    restart,
    restart_error: restartErr,
  });
});

// DELETE /api/rules/custom/:fileBase  (relative path inside custom dir)
app.delete("/api/rules/custom/:fileBase", async (req, res) => {
  const fb = safeName(req.params.fileBase);
  const customPath = path.join(CUSTOM_RULES_DIR, fb);
  const wazuhPath = path.join(WAZUH_RULES_DIR, fb);
  const yamlPath = path.join(CUSTOM_PLAYBOOKS_DIR, fb.replace(/\.xml$/, ".yml"));
  const removed = [];
  for (const p of [customPath, wazuhPath, yamlPath]) {
    try { await fsp.unlink(p); removed.push(p); } catch {}
  }
  // Try API delete as well in case fs unlink failed for wazuh path
  try {
    const token = await wazuhAuth();
    const u = new URL(`${WAZUH_API_URL}/manager/files`);
    u.searchParams.set("path", `etc/rules/${fb}`);
    await fetch(u, { method: "DELETE", headers: { Authorization: `Bearer ${token}` }, agent: insecureAgent });
  } catch {}
  rulesCache = null;
  if (WAZUH_AUTO_RESTART) { try { await restartWazuh(); } catch {} }
  res.json({ ok: true, removed });
});

// ─── Rule trigger: AI generates + executes a test command to fire the real detection ──
function execCmd(cmd, opts = {}) {
  return new Promise((resolve) => {
    require("child_process").exec(cmd, { timeout: 15000, shell: "/bin/bash", cwd: "/tmp", ...opts }, (err, stdout, stderr) => {
      resolve({ stdout: stdout || "", stderr: stderr || (err ? err.message : "") });
    });
  });
}

app.post("/api/rule/trigger", async (req, res) => {
  const { ruleId, ruleName, file, tactic, mitre, severity, preview, cmd: existingCmd } = req.body || {};
  if (!ruleId) return res.status(400).json({ error: "ruleId required" });

  try {
    // 1. Search for the rule file on disk
    const searchDirs = [RULES_LOCAL_ROOT, CUSTOM_RULES_DIR, WAZUH_RULES_DIR];
    let ruleContent = "";
    let foundPath = "";
    if (file) {
      for (const dir of searchDirs) {
        const fp = path.join(dir, file);
        if (fs.existsSync(fp)) { foundPath = fp; break; }
        const all = await walk(dir);
        const m = all.find(f => f.endsWith("/" + file) || f.endsWith("\\" + file));
        if (m) { foundPath = m; break; }
      }
      if (foundPath) {
        ruleContent = await fsp.readFile(foundPath, "utf-8");
        ruleContent = ruleContent.slice(0, 3000);
      }
    }

    // If this is an execution call (preview=false), use the existing cmd instead of regenerating
    let cmd = existingCmd || "";
    let summary = "";

    if (!cmd) {
      // 2a. AI generates a test command + summary explanation
      const genSys = "You are an adversary emulation engine. Given a SOC detection rule, output a JSON object.\n"
        + "Do NOT explain, reason, or add any text outside the JSON.\n"
        + "The JSON object must have exactly two string fields:\n"
        + '  "command": a single executable bash command (e.g. logger, curl, nc, ssh, echo)\n'
        + '  "summary": 1-2 sentences describing what the command simulates\n'
        + 'Example output: {"command":"logger -t sshd \\"Failed password for root\\"","summary":"Writes a fake SSH failure to syslog to trigger the brute-force rule."}\n'
        + 'Output ONLY the JSON object, nothing else.';

      let userMsg = `Generate test trigger for:\nID: ${ruleId}\nName: ${ruleName}\nFile: ${file || "—"}\nTactic: ${tactic || "—"}\nMITRE: ${mitre || "—"}\nSeverity: ${severity || "—"}\n\nRule content:\n${ruleContent || "(not found on disk)"}`;
      const { userInput } = req.body || {};
      if (userInput) userMsg += `\n\nUser refinement: ${userInput}`;

      const aiRaw = await callAi({ system: genSys, messages: [{ role: "user", content: userMsg }], max_tokens: 600 });

      // Extract JSON object from anywhere in the response (handles models that prepend reasoning text)
      let parsed = null;
      const jsonMatch = aiRaw.match(/\{[\s\S]*?\}/);
      if (jsonMatch) {
        try { parsed = JSON.parse(jsonMatch[0]); } catch { /* fall through */ }
      }
      if (!parsed) {
        try { parsed = JSON.parse(aiRaw.replace(/```(?:json)?\n?/gi, "").trim()); } catch { /* fall through */ }
      }
      if (parsed) {
        cmd = (parsed.command || "").trim();
        summary = (parsed.summary || "").trim();
      }

      // Validate cmd looks like a shell command (not reasoning text)
      const looksLikeCmd = cmd && cmd.length >= 3 && /^[a-zA-Z0-9_\/\.\-]/.test(cmd) && !/^(we |i |the |this |to |you |output|generate|here)/i.test(cmd);
      if (!looksLikeCmd) {
        // Last-resort: find a line that looks like a bash command
        const cmdLine = aiRaw.split("\n").find(l => /^(logger|echo|curl|nc|ssh|sudo|bash|sh|python|perl|ruby|nmap|wget|kill|systemctl|journalctl|auditctl|touch|mkdir|rm|cat|printf|openssl)\b/.test(l.trim()));
        if (cmdLine) { cmd = cmdLine.trim(); summary = summary || ""; }
        else throw new Error("AI did not generate a valid command");
      }
    }

    // Preview mode: return command + summary without executing
    if (preview) {
      return res.json({ ok: true, cmd, summary, preview: true });
    }

    // 3. Execute the command (timeboxed, sandboxed)
    const execResult = await execCmd(cmd);

    // 4. Inject alert so it appears immediately in OPXDR
    const sevOrder = { LOW: 1, MEDIUM: 5, HIGH: 8, CRITICAL: 12 };
    const lvl = sevOrder[severity] || 8;
    const ts = new Date().toISOString();
    const uid = `TRG-${Date.now()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;
    const alert = {
      id: uid, ruleId, ruleName: ruleName || ruleId, severity: severity || "HIGH", level: lvl,
      tactic: tactic || "—", mitre: mitre || "—", time: ts, srcIp: "—", dstIp: "—",
      account: "—", host: "trigger", agentId: "—", location: "rule_trigger",
      fullLog: `[trigger] ${cmd}`, decoder: "rule_trigger", iocs: [],
      groups: ["rule_trigger"], injected: true, raw: { ruleId, ruleName, cmd },
    };
    injectedAlerts.push(alert);
    if (injectedAlerts.length > 500) injectedAlerts.shift();
    alertEmitter.emit("alert", alert);

    res.json({ ok: true, id: uid, cmd, summary, stdout: execResult.stdout?.slice(0, 1000), stderr: execResult.stderr?.slice(0, 500) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/rule/read — read a rule file from disk
app.get("/api/rule/read", async (req, res) => {
  const { file } = req.query;
  if (!file) return res.status(400).json({ error: "file parameter required" });
  const searchDirs = [RULES_LOCAL_ROOT, CUSTOM_RULES_DIR, WAZUH_RULES_DIR];
  try {
    let foundPath = "";
    for (const dir of searchDirs) {
      const fp = path.join(dir, file);
      if (fs.existsSync(fp)) { foundPath = fp; break; }
      const all = await walk(dir);
      const m = all.find(f => f.endsWith("/" + file) || f.endsWith("\\" + file));
      if (m) { foundPath = m; break; }
    }
    if (!foundPath) return res.status(404).json({ error: `Rule file "${file}" not found in any search path` });
    const content = await fsp.readFile(foundPath, "utf-8");
    res.json({ file: foundPath, content });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/rule/save — save (overwrite) a rule file on disk
app.post("/api/rule/save", async (req, res) => {
  const { file, content } = req.body || {};
  if (!file || content == null) return res.status(400).json({ error: "file and content required" });
  const searchDirs = [RULES_LOCAL_ROOT, CUSTOM_RULES_DIR, WAZUH_RULES_DIR];
  try {
    let foundPath = "";
    for (const dir of searchDirs) {
      const fp = path.join(dir, file);
      if (fs.existsSync(fp)) { foundPath = fp; break; }
      const all = await walk(dir);
      const m = all.find(f => f.endsWith("/" + file) || f.endsWith("\\" + file));
      if (m) { foundPath = m; break; }
    }
    if (!foundPath) return res.status(404).json({ error: `Rule file "${file}" not found` });
    await fsp.writeFile(foundPath, content, "utf-8");
    res.json({ ok: true, file: foundPath, saved: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/wazuh/restart
app.post("/api/wazuh/restart", async (_req, res) => {
  try { res.json(await restartWazuh()); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/alerts/investigate?rule_id=12345&limit=10&min_level=8
app.get("/api/alerts/investigate", async (req, res) => {
  const ruleIdRaw = req.query.rule_id || "";
  const ruleId = ruleIdRaw.replace(/^WAZ-/, "");
  const limit = parseInt(req.query.limit || "10", 10);
  const minLevel = parseInt(req.query.min_level || "8", 10);

  if (WAZUH_INDEXER_PASS) {
    try {
      const auth = Buffer.from(`${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASS}`).toString("base64");
      const filter = [{ range: { "rule.level": { gte: minLevel } } }];
      if (ruleId) filter.push({ term: { "rule.id": ruleId } });
      const r = await fetch(`${WAZUH_INDEXER_URL}/${WAZUH_INDEXER_INDEX}/_search`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Basic ${auth}` },
        body: JSON.stringify({
          size: limit,
          query: { bool: { filter } },
          sort: [{ timestamp: { order: "desc" } }],
        }),
        agent: insecureAgent,
      });
      if (!r.ok) throw new Error(`Indexer ${r.status}: ${(await r.text()).slice(0, 200)}`);
      const j = await r.json();
      const alerts = (j.hits?.hits || []).map(parseIndexerHit).filter(Boolean);
      return res.json({ alerts, count: alerts.length, source: "indexer", rule_id: ruleId || null });
    } catch (e) {
      console.warn("[investigate] indexer failed:", e.message);
    }
  }

  // Fallback: alerts.json file
  try {
    if (!fs.existsSync(WAZUH_ALERTS_LOG)) {
      return res.json({ alerts: [], note: "alerts.json not readable", source: "file" });
    }
    const tail = spawn("tail", ["-n", String(limit * 10), WAZUH_ALERTS_LOG]);
    let buf = "";
    tail.stdout.on("data", d => (buf += d.toString()));
    tail.on("close", () => {
      let alerts = buf.split("\n").filter(l => l.trim()).map(parseAlertLine).filter(Boolean)
        .filter(a => (a.level || 0) >= minLevel);
      if (ruleId) alerts = alerts.filter(a =>
        a.ruleId === `WAZ-${ruleId}` || String(a.raw?.rule?.id) === ruleId
      );
      alerts = alerts.slice(-limit).reverse();
      res.json({ alerts, count: alerts.length, source: "file", rule_id: ruleId || null });
    });
    tail.on("error", e => res.status(500).json({ error: e.message }));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/investigate/full — aggregates all Wazuh telemetry for an alert
// Queries: host timeline, source-IP history, rule frequency, agent activity
// Params: host, src_ip, agent_id, rule_id, hours (default 48)
app.get("/api/investigate/full", async (req, res) => {
  const { host, src_ip, agent_id, rule_id, hours = "48" } = req.query;
  const since = new Date(Date.now() - parseInt(hours) * 3_600_000).toISOString();

  if (!WAZUH_INDEXER_PASS) {
    return res.json({ telemetry: null, note: "Wazuh Indexer not configured — set WAZUH_INDEXER_PASS in .env" });
  }

  const auth = Buffer.from(`${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASS}`).toString("base64");
  const timeFilter = { range: { timestamp: { gte: since } } };

  async function idx(must) {
    const r = await fetch(`${WAZUH_INDEXER_URL}/${WAZUH_INDEXER_INDEX}/_search`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Basic ${auth}` },
      body: JSON.stringify({
        size: 50,
        query: { bool: { filter: [timeFilter, ...must] } },
        sort: [{ timestamp: { order: "desc" } }],
      }),
      agent: insecureAgent,
    });
    if (!r.ok) throw new Error(`Indexer ${r.status}: ${(await r.text()).slice(0, 120)}`);
    return (await r.json()).hits?.hits?.map(parseIndexerHit).filter(Boolean) || [];
  }

  try {
    const cleanRuleId = (rule_id || "").replace(/^WAZ-/, "");
    const [hostAlerts, ipAlerts, ruleAlerts, agentAlerts] = await Promise.all([
      host && host !== "—"
        ? idx([{ term: { "agent.name": host } }])
        : Promise.resolve([]),
      src_ip && src_ip !== "—"
        ? idx([{ bool: { should: [{ term: { "data.srcip": src_ip } }, { term: { "data.src_ip": src_ip } }], minimum_should_match: 1 } }])
        : Promise.resolve([]),
      cleanRuleId
        ? idx([{ term: { "rule.id": cleanRuleId } }])
        : Promise.resolve([]),
      agent_id && agent_id !== "—"
        ? idx([{ term: { "agent.id": agent_id } }])
        : Promise.resolve([]),
    ]);

    // Compute quick stats
    const uniqHostsForRule = new Set(ruleAlerts.map(a => a.host)).size;
    const uniqIpsForRule   = new Set(ruleAlerts.map(a => a.srcIp).filter(v => v && v !== "—")).size;
    const hostSevCounts    = hostAlerts.reduce((m, a) => { m[a.severity] = (m[a.severity] || 0) + 1; return m; }, {});

    res.json({
      telemetry: {
        timeframe_hours: parseInt(hours),
        queried_at: new Date().toISOString(),
        host_alerts:  hostAlerts.slice(0, 30),
        ip_alerts:    ipAlerts.slice(0, 20),
        rule_alerts:  ruleAlerts.slice(0, 20),
        agent_alerts: agentAlerts.slice(0, 20),
        stats: {
          host_event_count:       hostAlerts.length,
          host_severity_breakdown: hostSevCounts,
          ip_event_count:         ipAlerts.length,
          rule_activation_count:  ruleAlerts.length,
          rule_unique_hosts:      uniqHostsForRule,
          rule_unique_src_ips:    uniqIpsForRule,
          agent_event_count:      agentAlerts.length,
        },
      },
    });
  } catch (e) {
    console.warn("[investigate/full]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// Public config — persisted geo API keys (frontend keys, stored server-side)
const GEO_KEYS_FILE = path.join(__dirname, "..", ".geo-keys.json");

function readGeoKeys() {
  try { return JSON.parse(fs.readFileSync(GEO_KEYS_FILE, "utf8")); } catch { return {}; }
}

app.get("/api/geo-config", (_req, res) => {
  const saved = readGeoKeys();
  res.json({ gmapsKey: process.env.VITE_GMAPS_KEY || saved.gmaps || "", ...saved });
});

app.post("/api/geo-config", express.json(), (req, res) => {
  try {
    const existing = readGeoKeys();
    const merged = { ...existing, ...req.body };
    // Never store empty strings — remove blank entries
    Object.keys(merged).forEach(k => { if (!merged[k]) delete merged[k]; });
    fs.writeFileSync(GEO_KEYS_FILE, JSON.stringify(merged, null, 2));
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Static (production)
const distPath = path.join(__dirname, "..", "dist");
if (fs.existsSync(distPath)) {
  app.use(express.static(distPath));
  app.get("*", (_req, res) => res.sendFile(path.join(distPath, "index.html")));
}

app.listen(PORT, "0.0.0.0", () => {
  console.log(`╔══════════════════════════════════════════════════╗`);
  console.log(`║  OPXDR backend                                   ║`);
  console.log(`║  http://100.86.115.94:${PORT}                       ║`);
  console.log(`╠══════════════════════════════════════════════════╣`);
  console.log(`  Wazuh API : ${WAZUH_API_URL} (insecure=${WAZUH_API_INSECURE})`);
  console.log(`  Rules root: ${RULES_LOCAL_ROOT}`);
  console.log(`  Alerts log: ${WAZUH_ALERTS_LOG}`);
  console.log(`  AI provider: ${process.env.OPENCODE_API_KEY ? "OpenCode" : process.env.ANTHROPIC_API_KEY ? "Anthropic" : "(none — set in .env)"}`);
  console.log(`  Slack     : ${SLACK_WEBHOOK_URL ? `enabled (${SLACK_CHANNEL})` : "(disabled — set SLACK_WEBHOOK_URL)"}`);
  console.log(`  AI auto   : ${AI_AUTO_REPORT ? `on (min level ${AI_AUTO_REPORT_MIN_LEVEL})` : "off"}`);
  if (AI_AUTO_REPORT) startAutoReportTail();
  loadPersistedAlerts();
  backfillHighCriticalAlerts();
  setInterval(pollHighCriticalAlerts, 60_000);
});
