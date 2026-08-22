import { useContext, useEffect, useState } from "react";
import { OpxdrContext } from "../App";
import {
  Eye, Search, RefreshCw, AlertTriangle, Lock, Send, X,
  Globe, Activity, Database, ExternalLink, ChevronRight,
} from "../lib/icons";
import { callAgent } from "../lib/api";

// Synthetic leak / darkweb data (replace with real Tor crawler feed when available)
const LEAK_CATEGORIES = [
  { id: "ransomware",  label: "Ransomware Leaks", icon: "🔒", color: "#ef4444", count: 47 },
  { id: "credentials", label: "Credential Dumps", icon: "🔑", color: "#f59e0b", count: 128 },
  { id: "databases",   label: "Database Dumps",   icon: "🗄",  color: "#a855f7", count: 31 },
  { id: "marketplaces",label: "Marketplaces",     icon: "🏴", color: "#06b6d4", count: 14 },
  { id: "forums",      label: "Forums Monitor",   icon: "💬", color: "#22c55e", count: 22 },
];

const SAMPLE_LEAKS = [
  { id: "L-001", category: "ransomware",  title: "LockBit 3.0 — Acme Corp data leaked",         victim: "Acme Corp",       size: "240 GB",  posted: "2h ago",  severity: "CRITICAL", source: "lockbitapt.onion" },
  { id: "L-002", category: "credentials", title: "RaidForums dump — 4.2M Pegasus credentials",  victim: "Pegasus Airlines",size: "1.2 GB",  posted: "4h ago",  severity: "HIGH",     source: "breachforums.onion" },
  { id: "L-003", category: "ransomware",  title: "BlackCat — Energy sector victim",             victim: "Anonymous",       size: "78 GB",   posted: "8h ago",  severity: "CRITICAL", source: "alphvmmm.onion" },
  { id: "L-004", category: "databases",   title: "MySQL dump — Healthcare provider PII",        victim: "Anonymous",       size: "4.5 GB",  posted: "12h ago", severity: "CRITICAL", source: "dread.onion" },
  { id: "L-005", category: "credentials", title: "Combo list — Fortune 500 employee accounts",  victim: "Multiple",        size: "880 MB",  posted: "1d ago",  severity: "HIGH",     source: "telegram channel" },
  { id: "L-006", category: "marketplaces",title: "Genesis Market — banking botnet logs",        victim: "Banking sector",  size: "—",        posted: "1d ago",  severity: "HIGH",     source: "genesis.onion" },
  { id: "L-007", category: "forums",      title: "BreachForums — discussion of new APT toolkit",victim: "—",               size: "—",        posted: "2d ago", severity: "MEDIUM",   source: "breachforums.is" },
  { id: "L-008", category: "ransomware",  title: "Clop — Fortinet customer data",               victim: "Fortinet client", size: "120 GB",  posted: "3d ago",  severity: "CRITICAL", source: "clop.onion" },
];

const ACTIVE_CAMPAIGNS = [
  { name: "LockBit 3.0",  victims: 1247, status: "active",  region: "Global" },
  { name: "BlackCat/ALPHV",victims: 412,  status: "active",  region: "NA, EU" },
  { name: "Clop",          victims: 308,  status: "active",  region: "Global" },
  { name: "Play",          victims: 187,  status: "active",  region: "EU, NA" },
  { name: "Akira",         victims: 95,   status: "growing", region: "Global" },
];

const SEV_C = {
  CRITICAL: "text-sev-critical", HIGH: "text-sev-high",
  MEDIUM: "text-sev-medium", LOW: "text-sev-low",
};

export default function TorMonitorPage() {
  const { savedDocs, setSavedDocs } = useContext(OpxdrContext);
  const [category, setCategory] = useState("all");
  const [search, setSearch] = useState("");
  const [activeLeak, setActiveLeak] = useState(null);
  const [investigation, setInvestigation] = useState("");
  const [streaming, setStreaming] = useState(false);

  const filtered = SAMPLE_LEAKS.filter(l =>
    (category === "all" || l.category === category) &&
    (!search || l.title.toLowerCase().includes(search.toLowerCase()) || l.victim.toLowerCase().includes(search.toLowerCase()))
  );

  async function investigate(leak) {
    setActiveLeak(leak);
    setInvestigation("");
    setStreaming(true);
    try {
      const sys = "You are a SOC analyst monitoring darkweb leaks. Produce: 1) Victim impact assessment, 2) Data exposure analysis, 3) Recommended response actions, 4) Notification requirements. Be concise and actionable.";
      const msg = `Darkweb leak detected:\nTitle: ${leak.title}\nVictim: ${leak.victim}\nCategory: ${leak.category}\nSize: ${leak.size}\nSource: ${leak.source}\nPosted: ${leak.posted}`;
      await callAgent("investigate", [{ role: "user", content: msg }], (chunk) => setInvestigation(chunk), { system: sys });
    } catch (e) {
      setInvestigation(`[Investigation failed: ${e.message}]`);
    }
    setStreaming(false);
  }

  function saveToDocuments() {
    if (!activeLeak || !investigation) return;
    const doc = {
      id: `DOC-${Date.now()}`,
      title: `Tor Investigation: ${activeLeak.title}`,
      created: new Date().toISOString(),
      report: investigation,
      alert: {
        id: activeLeak.id,
        severity: activeLeak.severity,
        ruleName: activeLeak.title,
      },
    };
    setSavedDocs([doc, ...savedDocs]);
    alert(`Saved as ${doc.id}`);
  }

  return (
    <div className="p-5">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="w-11 h-11 rounded-md bg-sev-critical/15 border border-sev-critical/40 flex items-center justify-center">
            <Eye size={20} className="text-sev-critical" />
          </div>
          <div>
            <h1 className="text-xl font-extrabold text-ink-0">TOR MONITOR</h1>
            <p className="text-2xs text-ink-3">Darkweb leak intelligence · Threat actor surveillance</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-2xs text-ink-3">
            <span className="live-dot mr-1" /> {SAMPLE_LEAKS.length} leaks tracked
          </span>
          <button className="btn btn-outline">
            <RefreshCw size={13} /> Refresh
          </button>
        </div>
      </div>

      {/* Category stats */}
      <div className="grid grid-cols-5 gap-3 mb-5">
        {LEAK_CATEGORIES.map(c => (
          <button
            key={c.id}
            onClick={() => setCategory(category === c.id ? "all" : c.id)}
            className={`panel p-3 text-left transition ${category === c.id ? "border-brand bg-bg-2" : "hover:bg-bg-2"}`}
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-base">{c.icon}</span>
              <span className="text-3xs font-mono text-ink-3 uppercase tracking-wider">{c.label.split(" ")[0]}</span>
            </div>
            <div className="text-xl font-extrabold tabular-nums" style={{ color: c.color }}>{c.count}</div>
            <div className="text-3xs text-ink-3 mt-0.5">{c.label.split(" ").slice(1).join(" ")}</div>
          </button>
        ))}
      </div>

      <div className="grid grid-cols-12 gap-4">
        {/* Left/center — leak feed */}
        <div className="col-span-8 space-y-3">
          {/* Search */}
          <div className="panel">
            <div className="panel-header">
              <div className="flex items-center gap-2">
                <span className="live-dot" style={{ background: "#ef4444" }} />
                <span className="panel-title">Live Leak Feed</span>
                <span className="text-2xs text-ink-3">— {filtered.length} entries</span>
              </div>
              <div className="relative">
                <Search size={11} className="absolute left-2 top-1/2 -translate-y-1/2 text-ink-3" />
                <input
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder="Filter..."
                  className="bg-bg-2 border border-border rounded pl-6 pr-2 py-1 text-2xs text-ink-0 w-48 outline-none focus:border-brand"
                />
              </div>
            </div>
            <div className="divide-y divide-border max-h-[60vh] overflow-y-auto">
              {filtered.map(leak => {
                const cat = LEAK_CATEGORIES.find(c => c.id === leak.category);
                return (
                  <div
                    key={leak.id}
                    onClick={() => investigate(leak)}
                    className="p-3 hover:bg-bg-2 cursor-pointer flex items-start gap-3"
                  >
                    <div className="w-1 self-stretch rounded-full flex-shrink-0" style={{ background: cat?.color || "#64748b" }} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <span className="text-base flex-shrink-0">{cat?.icon}</span>
                        <span className="text-sm font-bold text-ink-0">{leak.title}</span>
                        <span className={`badge ${leak.severity === "CRITICAL" ? "badge-critical" : leak.severity === "HIGH" ? "badge-high" : "badge-medium"}`}>
                          {leak.severity}
                        </span>
                        <span className="text-3xs text-ink-3 font-mono ml-auto">{leak.posted}</span>
                      </div>
                      <div className="grid grid-cols-4 gap-2 mt-2">
                        <Field k="victim" v={leak.victim} />
                        <Field k="size" v={leak.size} />
                        <Field k="source" v={leak.source} mono />
                        <Field k="category" v={cat?.label || leak.category} />
                      </div>
                      <div className="flex gap-1.5 mt-2">
                        <button
                          onClick={(e) => { e.stopPropagation(); investigate(leak); }}
                          className="btn btn-accent text-2xs"
                        >
                          <Eye size={11} /> Investigate
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Right — campaigns + investigation drawer */}
        <div className="col-span-4 space-y-3">
          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">Active Campaigns</span>
            </div>
            <div className="p-3 space-y-2">
              {ACTIVE_CAMPAIGNS.map(c => (
                <div key={c.name} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className={`w-1.5 h-1.5 rounded-full ${c.status === "active" ? "bg-sev-critical" : "bg-sev-high"}`} />
                    <span className="text-xs text-ink-0 font-semibold">{c.name}</span>
                  </div>
                  <div className="text-right">
                    <div className="text-xs font-mono text-sev-critical">{c.victims}</div>
                    <div className="text-3xs text-ink-3">{c.region}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Investigation drawer */}
          {activeLeak && (
            <div className="panel">
              <div className="panel-header">
                <span className="panel-title">Investigation</span>
                <button onClick={() => { setActiveLeak(null); setInvestigation(""); }} className="text-ink-3 hover:text-ink-0">
                  <X size={14} />
                </button>
              </div>
              <div className="p-3">
                <div className="text-xs text-ink-0 font-semibold mb-1">{activeLeak.title}</div>
                <div className="text-3xs text-ink-3 font-mono mb-3">
                  {activeLeak.victim} · {activeLeak.size} · {activeLeak.source}
                </div>
                {streaming && (
                  <div className="text-2xs text-brand-accent mb-2 flex items-center gap-1.5">
                    <RefreshCw size={11} className="animate-spin" /> Agent investigating...
                  </div>
                )}
                {investigation && (
                  <>
                    <pre className="whitespace-pre-wrap text-2xs text-ink-1 font-mono bg-bg-0 border border-border rounded p-2.5 max-h-72 overflow-y-auto">
                      {investigation}
                    </pre>
                    {!streaming && (
                      <button onClick={saveToDocuments} className="btn btn-outline w-full text-2xs mt-2">
                        💾 Save to Documents
                      </button>
                    )}
                  </>
                )}
              </div>
            </div>
          )}

          {/* Onion services quick-access */}
          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">Monitored Sources</span>
            </div>
            <div className="p-3 space-y-1.5">
              {["lockbitapt.onion", "alphvmmm.onion", "clop.onion", "breachforums.is", "dread.onion", "genesis.onion"].map(s => (
                <div key={s} className="flex items-center justify-between text-2xs font-mono">
                  <span className="text-ink-2">{s}</span>
                  <span className="live-dot" />
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function Field({ k, v, mono }) {
  return (
    <div className="bg-bg-2 border border-border rounded px-2 py-1">
      <div className="text-3xs text-ink-3 uppercase tracking-wider">{k}</div>
      <div className={`text-2xs ${mono ? "font-mono" : ""} text-ink-1 truncate`}>{v}</div>
    </div>
  );
}
