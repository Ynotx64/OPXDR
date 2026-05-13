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
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { EventEmitter } from "node:events";
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

app.get("/api/alerts/recent", async (req, res) => {
  const limit    = parseInt(req.query.limit     || "500", 10);
  const minLevel = parseInt(req.query.min_level || String(ALERT_MIN_LEVEL), 10);

  // Always include injected alerts (newest first, up to limit)
  const injected = [...injectedAlerts].reverse().slice(0, limit);

  // Primary: Wazuh Indexer (OpenSearch)
  if (WAZUH_INDEXER_PASS) {
    try {
      const result = await queryIndexer({ minLevel, size: limit });
      const wazuhAlerts = (result.hits?.hits || []).map(parseIndexerHit).filter(Boolean);
      // Deduplicate Wazuh alerts by id, then merge with injected
      const seen = new Set(injected.map(a => a.id));
      const dedupedWazuh = wazuhAlerts.filter(a => { if(seen.has(a.id))return false; seen.add(a.id); return true; });
      const merged = [...injected, ...dedupedWazuh].slice(0, limit);
      return res.json({ alerts: merged, count: merged.length, min_level: minLevel, source: "indexer" });
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
        .slice(-limit)
        .reverse();
      const seen = new Set(injected.map(a => a.id));
      const merged = [...injected, ...fileAlerts.filter(a => !seen.has(a.id))].slice(0, limit);
      res.json({ alerts: merged, count: merged.length, min_level: minLevel, source: "file" });
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
app.post("/api/alerts/inject", (req, res) => {
  const b = req.body || {};
  if (!b.ruleName && !b.ruleId) return res.status(400).json({ error: "ruleName or ruleId required" });

  const sev  = (b.severity || "HIGH").toUpperCase();
  const lvl  = sevOrder[sev] ?? 8;
  const ts   = b.time || new Date().toISOString();
  const uid  = `INJ-${ts.replace(/[^0-9]/g, "").slice(0, 14)}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;

  const alert = {
    id:       uid,
    ruleId:   b.ruleId   || `CUSTOM-${uid.slice(-6)}`,
    ruleName: b.ruleName || b.ruleId || "Custom Detection",
    severity: sev,
    level:    lvl,
    tactic:   b.tactic   || "—",
    mitre:    b.mitre    || "—",
    time:     ts,
    srcIp:    b.srcIp    || "—",
    dstIp:    b.dstIp    || "—",
    account:  b.account  || "—",
    host:     b.host     || "—",
    agentId:  b.agentId  || "—",
    location: b.location || "—",
    fullLog:  b.fullLog  || b.raw_log || "",
    decoder:  b.decoder  || "—",
    iocs:     Array.isArray(b.iocs) ? b.iocs : [],
    groups:   Array.isArray(b.groups) ? b.groups : [],
    injected: true,
    raw:      b,
  };

  injectedAlerts.push(alert);
  if (injectedAlerts.length > 500) injectedAlerts.shift();
  alertEmitter.emit("alert", alert);
  console.log(`[inject] ${alert.severity} — ${alert.ruleName}`);
  res.json({ ok: true, id: alert.id, alert });
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
  const models = ["nemotron-3-super-free", "minimax-m2.5-free", "hy3-preview-free"];
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
//   - nemotron-3-super-free (NVIDIA Nemotron 3 Super 120B): excellent reasoning, large context
//                                                            → investigate, slackReport, irPlaybook, ruleAssistant
//   - minimax-m2.5-free (MiniMax M2.7, 460B MoE):           strong instruction following, fast
//                                                            → logAnalysis, validate
//   - hy3-preview-free (stealth Hy3):                        backup
//   - ling-2.6-flash-free (InclusionAI Ling 2.6 Flash):      backup
//   - big-pickle (DeepSeek-V4 Flash stealth):                backup, very fast
const AGENT_CFG = {
  investigate:   { models: ["nemotron-3-super-free", "minimax-m2.5-free", "hy3-preview-free"],         tokens: 4096 },
  logAnalysis:   { models: ["minimax-m2.5-free",     "ling-2.6-flash-free", "big-pickle"],             tokens: 2048 },
  slackReport:   { models: ["nemotron-3-super-free", "minimax-m2.5-free", "hy3-preview-free"],         tokens: 4096 },
  ruleAssistant: { models: ["nemotron-3-super-free", "minimax-m2.5-free", "hy3-preview-free"],         tokens: 3000 },
  irPlaybook:    { models: ["nemotron-3-super-free", "minimax-m2.5-free", "hy3-preview-free"],         tokens: 6000 },
  validate:      { models: ["nemotron-3-super-free", "minimax-m2.5-free", "claude-haiku-4-5"],         tokens: 4096 },
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

// ─── Rule trigger: AI generates + executes a test command to fire the real detection ──
function execCmd(cmd, opts = {}) {
  return new Promise((resolve) => {
    require("child_process").exec(cmd, { timeout: 15000, shell: "/bin/bash", cwd: "/tmp", ...opts }, (err, stdout, stderr) => {
      resolve({ stdout: stdout || "", stderr: stderr || (err ? err.message : "") });
    });
  });
}

app.post("/api/rule/trigger", async (req, res) => {
  const { ruleId, ruleName, file, tactic, mitre, severity } = req.body || {};
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
        // Search recursively by filename
        const all = await walk(dir);
        const m = all.find(f => f.endsWith("/" + file) || f.endsWith("\\" + file));
        if (m) { foundPath = m; break; }
      }
      if (foundPath) {
        ruleContent = await fsp.readFile(foundPath, "utf-8");
        ruleContent = ruleContent.slice(0, 3000); // keep context manageable
      }
    }

    // 2. AI generates a test command based on the rule
    const sysPrompt = "You are an adversary emulation engine. Given a SOC detection rule, generate a SINGLE realistic but safe bash command that would trigger this rule in Wazuh. "
      + "Use: logger (for log-based rules), curl/wget (for web rules), nc/ssh (for network rules), or similar. "
      + "Return ONLY the raw command — no markdown, no backticks, no explanation. The command must be a single line.";

    const userMsg = `Generate a test trigger command for this rule:\nID: ${ruleId}\nName: ${ruleName}\nFile: ${file || "—"}\nTactic: ${tactic || "—"}\nMITRE: ${mitre || "—"}\nSeverity: ${severity || "—"}\n\nRule content:\n${ruleContent || "(not found on disk)"}`;

    const cmd = (await callAi({ system: sysPrompt, messages: [{ role: "user", content: userMsg }], max_tokens: 500 }))
      .replace(/```(?:bash|sh)?\n?/gi, "").trim().split("\n")[0];

    if (!cmd || cmd.length < 3) throw new Error("AI did not generate a valid command");

    // 3. Execute the command (timeboxed, sandboxed)
    const execResult = await execCmd(cmd);

    // 4. Also inject an alert so it appears immediately in OPXDR
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

    res.json({ ok: true, id: uid, cmd, stdout: execResult.stdout?.slice(0, 1000), stderr: execResult.stderr?.slice(0, 500) });
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
});
