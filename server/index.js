// OPXDR — backend
// Provides:
//   GET  /api/health
//   GET  /api/rules               — local files merged with Wazuh API rules
//   GET  /api/rules/:id           — single rule detail (with raw XML/YAML)
//   GET  /api/playbooks           — IR playbooks discovered on disk
//   GET  /api/alerts/recent       — last N alerts from alerts.json
//   GET  /api/alerts/stream       — SSE feed tailing alerts.json
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
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
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

async function wazuh(pathName, params = {}) {
  const token = await wazuhAuth();
  const url = new URL(`${WAZUH_API_URL}${pathName}`);
  for (const [k, v] of Object.entries(params)) if (v != null) url.searchParams.set(k, String(v));
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
    agent: insecureAgent,
  });
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
  if (n >= 8) return "MEDIUM";
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
  try { await wazuhAuth(); wazuh = "ok"; } catch (e) { wazuh = e.message; }
  res.json({
    ok: true,
    wazuh,
    wazuh_url: WAZUH_API_URL,
    rules_root: RULES_LOCAL_ROOT,
    alerts_log: WAZUH_ALERTS_LOG,
    ai_provider: process.env.OPENCODE_API_KEY ? "opencode" : process.env.ANTHROPIC_API_KEY ? "anthropic" : "none",
    slack_enabled: !!SLACK_WEBHOOK_URL,
    ai_auto_report: AI_AUTO_REPORT,
    ai_auto_report_min_level: AI_AUTO_REPORT_MIN_LEVEL,
  });
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

app.get("/api/alerts/recent", async (req, res) => {
  const limit = parseInt(req.query.limit || "30", 10);
  try {
    if (!fs.existsSync(WAZUH_ALERTS_LOG)) {
      return res.json({ alerts: [], note: "alerts.json not readable — start with sudo or fix perms" });
    }
    // Use tail to get last N lines without loading the whole file
    const tail = spawn("tail", ["-n", String(limit * 2), WAZUH_ALERTS_LOG]);
    let buf = "";
    tail.stdout.on("data", (d) => (buf += d.toString()));
    tail.on("close", () => {
      const alerts = buf
        .split("\n")
        .filter((l) => l.trim())
        .map(parseAlertLine)
        .filter(Boolean)
        .slice(-limit)
        .reverse();
      res.json({ alerts, count: alerts.length });
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

  if (!fs.existsSync(WAZUH_ALERTS_LOG)) {
    res.write(`event: error\ndata: ${JSON.stringify({ msg: "alerts.json not readable", path: WAZUH_ALERTS_LOG })}\n\n`);
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
      if (a) res.write(`data: ${JSON.stringify(a)}\n\n`);
    }
  });
  tail.stderr.on("data", (d) => console.warn("[tail]", d.toString().trim()));
  const ka = setInterval(() => res.write(`: keepalive\n\n`), 25_000);
  req.on("close", () => { clearInterval(ka); tail.kill(); });
});

// ─── AI provider helpers (shared by /api/claude proxy + auto-report) ─────
function aiProvider() {
  const useOpenCode = !!process.env.OPENCODE_API_KEY;
  if (!useOpenCode && !process.env.ANTHROPIC_API_KEY) return null;
  return {
    useOpenCode,
    apiKey: useOpenCode ? process.env.OPENCODE_API_KEY : process.env.ANTHROPIC_API_KEY,
    apiUrl: useOpenCode
      ? (process.env.OPENCODE_API_URL || "https://api.opencode.ai/v1/messages")
      : (process.env.ANTHROPIC_API_URL || "https://api.anthropic.com/v1/messages"),
    model: useOpenCode
      ? (process.env.OPENCODE_MODEL || "claude-sonnet-4-20250514")
      : (process.env.ANTHROPIC_MODEL || "claude-sonnet-4-20250514"),
  };
}

function aiHeaders(p) {
  return p.useOpenCode
    ? { "Content-Type": "application/json", Authorization: `Bearer ${p.apiKey}` }
    : { "Content-Type": "application/json", "x-api-key": p.apiKey, "anthropic-version": "2023-06-01" };
}

// Non-streaming AI call. Returns the assembled text or throws.
async function callAi({ system, messages, max_tokens = 1200 }) {
  const p = aiProvider();
  if (!p) throw new Error("No AI key configured");
  const r = await fetch(p.apiUrl, {
    method: "POST",
    headers: aiHeaders(p),
    body: JSON.stringify({ model: p.model, max_tokens, system, messages, stream: false }),
  });
  if (!r.ok) throw new Error(`AI ${r.status}: ${await r.text()}`);
  const j = await r.json();
  // Anthropic + OpenCode both return { content: [{ type: "text", text: "..." }, ...] }
  const text = (j.content || []).filter((c) => c.type === "text").map((c) => c.text).join("");
  return text || JSON.stringify(j);
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

// ─── Slack notifications ──────────────────────────────────────────────────
const SEV_COLORS = { CRITICAL: "#dc2626", HIGH: "#f97316", MEDIUM: "#fbbf24", LOW: "#64748b" };
const SEV_EMOJI = { CRITICAL: ":rotating_light:", HIGH: ":warning:", MEDIUM: ":large_orange_diamond:", LOW: ":small_blue_diamond:" };

function buildSlackPayload(alert, reportText) {
  const sev = alert.severity || "HIGH";
  const color = SEV_COLORS[sev] || SEV_COLORS.HIGH;
  const emoji = SEV_EMOJI[sev] || ":warning:";
  const iocLine = (alert.iocs || []).map((i) => `[${i.t}] ${i.v}`).join("  ") || "—";
  const headline = `${emoji} *${sev}* — ${alert.ruleName} (\`${alert.ruleId}\`)`;
  const fields = [
    { title: "Tactic", value: alert.tactic || "—", short: true },
    { title: "MITRE", value: alert.mitre || "—", short: true },
    { title: "Source IP", value: alert.srcIp || "—", short: true },
    { title: "Dest IP", value: alert.dstIp || "—", short: true },
    { title: "Account", value: alert.account || "—", short: true },
    { title: "Host", value: alert.host || "—", short: true },
    { title: "IOCs", value: iocLine, short: false },
  ];
  const attachments = [{
    color,
    fallback: `${sev} ${alert.ruleName}`,
    title: alert.ruleName,
    text: headline,
    fields,
    footer: `OPXDR • alert ${alert.id} • ${alert.time}`,
    mrkdwn_in: ["text", "fields"],
  }];
  if (reportText) {
    // Slack attachments cap each text field around 4k; truncate just in case.
    const trimmed = reportText.length > 3500 ? reportText.slice(0, 3500) + "\n…(truncated)" : reportText;
    attachments.push({
      color: "#38bdf8",
      title: ":zap: AI Agent Report",
      text: trimmed,
      mrkdwn_in: ["text"],
    });
  }
  return {
    channel: SLACK_CHANNEL,
    username: SLACK_USERNAME,
    icon_emoji: ":shield:",
    text: headline,
    attachments,
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

async function tryWriteWazuh(filename, xml) {
  // Try direct filesystem write to /var/ossec/etc/rules; if denied, fall back to API.
  const target = path.join(WAZUH_RULES_DIR, filename);
  try {
    await fsp.writeFile(target, xml, { mode: 0o660 });
    return { method: "fs", path: target };
  } catch (e) {
    // Fall back to Wazuh API: PUT /manager/files?path=etc/rules/<file>&overwrite=true
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
      throw new Error(`fs error: ${e.message} | api error: ${apiErr.message}`);
    }
  }
}

async function restartWazuh() {
  const token = await wazuhAuth();
  const res = await fetch(`${WAZUH_API_URL}/manager/restart`, {
    method: "PUT",
    headers: { Authorization: `Bearer ${token}` },
    agent: insecureAgent,
  });
  if (!res.ok) throw new Error(`restart failed ${res.status}: ${await res.text()}`);
  return res.json();
}

// POST /api/rules/custom
// body: { ruleId, name, severity, tactic, mitre, xml, yaml, group }
app.post("/api/rules/custom", async (req, res) => {
  const { ruleId, name, severity = "HIGH", tactic = "Defense Evasion", mitre = "", xml, yaml, group = "custom_detection" } = req.body || {};
  if (!ruleId || !xml) return res.status(400).json({ error: "ruleId and xml are required" });

  const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const fileBase = `custom_${safeName(group)}_${safeName(ruleId)}_${stamp}.xml`;

  // 1. Save in our custom dir (always works, source of truth for the app)
  const customPath = path.join(CUSTOM_RULES_DIR, fileBase);
  await fsp.writeFile(customPath, xml, "utf8");

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

// POST /api/wazuh/restart
app.post("/api/wazuh/restart", async (_req, res) => {
  try { res.json(await restartWazuh()); }
  catch (e) { res.status(500).json({ error: e.message }); }
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
});
