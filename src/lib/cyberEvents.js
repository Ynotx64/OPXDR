// Cyber threat event generator + live feed fetcher
// Ported from CYBER.* in geo.html, restructured for React
import { GEO_BY_CC } from "/src/data/geoData.js";

export const CYBER_COLORS = {
  webAttackers: "#ff2d55", ddosAttackers: "#ff9f0a", intruders: "#a855f7",
  scanners: "#06b6d4", cyberOAS: "#22c55e", cyberODS: "#84cc16",
  cyberMAV: "#f59e0b", cyberWAV: "#ef4444", cyberIDS: "#ff6b35",
  cyberVUL: "#fbbf24", cyberRMW: "#dc2626", shodanDevices: "#f59e0b",
  honeypot: "#ff7a18",
};

const CVE_MAP = {
  webAttackers: ["CVE-2024-3400", "CVE-2023-46805", "CVE-2022-22965"],
  ddosAttackers: ["CVE-2022-26134", "CVE-2023-34362"],
  intruders: ["CVE-2021-44228", "CVE-2023-46604", "CVE-2024-1709"],
  scanners: ["CVE-2022-1388", "CVE-2024-24919"],
  cyberOAS: ["CVE-2024-21412", "CVE-2023-36584"],
  cyberODS: ["CVE-2023-23397"],
  cyberMAV: ["CVE-2024-30103"],
  cyberWAV: ["CVE-2021-44228"],
  cyberIDS: ["CVE-2024-3400"],
  cyberVUL: ["CVE-2024-3400", "CVE-2023-46805"],
  cyberRMW: ["CVE-2021-34527", "CVE-2024-26234"],
  shodanDevices: ["CVE-2023-20198"],
  honeypot: ["CVE-2022-1388"],
};

const MALWARE_MAP = {
  webAttackers: ["Cobalt Strike", "Beacon", "Silver"],
  ddosAttackers: ["Mirai", "Killnet", "Fodcha"],
  intruders: ["Cobalt Strike", "PlugX", "QuasarRAT"],
  scanners: ["Masscan", "Zmap", "Shodan"],
  cyberOAS: ["Redline Stealer", "Lumma Stealer", "Vidar"],
  cyberODS: ["Cobalt Strike", "Brute Ratel", "Sliver"],
  cyberMAV: ["QakBot", "Emotet", "IcedID"],
  cyberWAV: ["SocGholish", "ClearFake", "FakeUpdates"],
  cyberIDS: ["Turla", "StrongPity", "OilRig"],
  cyberVUL: ["Log4Shell", "ProxyNotShell"],
  cyberRMW: ["LockBit 3.0", "BlackCat", "Clop", "Play"],
  shodanDevices: ["Mirai", "Muhstik"],
  honeypot: ["Zmap", "Credential Probe", "Relay Probe", "Share Scanner"],
};

const ACTOR_MAP = {
  webAttackers: ["FIN7", "TA505", "UNC1878"],
  ddosAttackers: ["Killnet", "Anonymous Sudan", "NoName057(16)"],
  intruders: ["APT29", "APT41", "Lazarus", "Volt Typhoon"],
  scanners: ["Unknown", "Shodan", "Censys"],
  cyberOAS: ["TA505", "Wizard Spider"],
  cyberODS: ["APT41", "APT33"],
  cyberMAV: ["TA542", "Muddled Libra"],
  cyberWAV: ["FIN7", "TA569"],
  cyberIDS: ["Turla", "APT34"],
  cyberVUL: ["Unknown", "APT29"],
  cyberRMW: ["LockBitSupp", "BlackCat", "Clop"],
  shodanDevices: ["Mirai", "Unknown"],
  honeypot: ["Unknown"],
};

function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

function genIP(cc) {
  const r = { US: [98, 100], CN: [1, 5], RU: [2, 5], DE: [80, 90] };
  const range = r[cc] || [0, 255];
  const first = range[0] + Math.floor(Math.random() * (range[1] - range[0] + 1));
  return `${first}.${Math.floor(Math.random()*254)+1}.${Math.floor(Math.random()*254)+1}.${Math.floor(Math.random()*254)+1}`;
}

function genEvent(type, srcCC, dstCC, sev = "medium") {
  const src = GEO_BY_CC[srcCC] || { lat: 0, lng: 0, name: "Unknown" };
  const dst = GEO_BY_CC[dstCC] || { lat: 0, lng: 0, name: "Unknown" };
  return {
    id: `${type}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    type, severity: sev,
    src: { ...src, cc: srcCC, ip: genIP(srcCC) },
    dst: { ...dst, cc: dstCC, port: pick([22, 80, 443, 445, 3389, 8080]) },
    cve: pick(CVE_MAP[type] || [""]),
    malware: pick(MALWARE_MAP[type] || [""]),
    actor: pick(ACTOR_MAP[type] || [""]),
    timestamp: new Date().toISOString(),
    createdAt: Date.now() - Math.random() * 4000,
    color: CYBER_COLORS[type] || "#06b6d4",
  };
}

export function canonicalType(type) {
  if (type === "cyberRMW") return "ransomware";
  if (type === "intruders" || type === "webAttackers") return "ssh";
  if (type === "honeypot") return "scanner";
  if (type === "scanners" || type === "shodanDevices" || type === "cyberVUL") return "scanner";
  if (type === "cyberMAV" || type === "cyberWAV" || type === "cyberOAS" || type === "cyberODS" || type === "cyberIDS") return "malware";
  if (type === "ddosAttackers") return "botnet";
  return "scanner";
}

const COUNTRIES = ["US", "CN", "RU", "DE", "NL", "IR", "UA", "GB", "BR", "IN", "JP", "KP"];

export function generateInitialEvents(count = 40) {
  const events = [];
  const types = Object.keys(CYBER_COLORS);
  for (let i = 0; i < count; i++) {
    const type = pick(types);
    const srcCC = pick(COUNTRIES);
    let dstCC = pick(COUNTRIES);
    while (dstCC === srcCC) dstCC = pick(COUNTRIES);
    const sev = pick(["medium", "high", "high", "critical"]);
    events.push(genEvent(type, srcCC, dstCC, sev));
  }
  return events;
}

export function generateOneEvent() {
  const types = Object.keys(CYBER_COLORS);
  const type = pick(types);
  const srcCC = pick(COUNTRIES);
  let dstCC = pick(COUNTRIES);
  while (dstCC === srcCC) dstCC = pick(COUNTRIES);
  return genEvent(type, srcCC, dstCC, pick(["medium", "high", "critical"]));
}

// Try real OSINT feeds — falls back to synthetic on failure
export async function fetchRealCyberFeed() {
  const events = [];
  try {
    // DShield top attacked IPs
    const r = await fetch("https://isc.sans.edu/api/topips/attacks?limit=10&json", { signal: AbortSignal.timeout(5000) });
    if (r.ok) {
      const data = await r.json();
      const list = Array.isArray(data) ? data : (data.data || []);
      list.slice(0, 10).forEach((e, i) => {
        const ev = generateOneEvent();
        ev.type = "scanners";
        ev.src.ip = e.ip || ev.src.ip;
        ev.feed = "DShield";
        events.push(ev);
      });
    }
  } catch {}
  try {
    // CISA KEV — known exploited vulnerabilities
    const r = await fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", { signal: AbortSignal.timeout(5000) });
    if (r.ok) {
      const data = await r.json();
      (data.vulnerabilities || []).slice(0, 15).forEach(v => {
        const ev = generateOneEvent();
        ev.type = "cyberVUL";
        ev.cve = v.cveID;
        ev.feed = "CISA KEV";
        events.push(ev);
      });
    }
  } catch {}
  return events;
}


export async function fetchHoneypotCyberFeed({ limit = 100, since = null, agentIds = [] } = {}) {
  const qs = new URLSearchParams({ limit: String(limit) });
  if (since) qs.set("since", since);
  if (agentIds.length) qs.set("agentIds", agentIds.join(","));
  try {
    const r = await fetch(`/api/honeypot/events?${qs.toString()}`, { signal: AbortSignal.timeout(5000) });
    if (!r.ok) return [];
    const data = await r.json();
    return Array.isArray(data.events) ? data.events : [];
  } catch {
    return [];
  }
}
