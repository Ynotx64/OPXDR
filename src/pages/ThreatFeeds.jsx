import { useEffect, useMemo, useState } from "react";
import { Network, Server, Download, RefreshCw, Shield, Activity, WifiOff, Copy } from "../lib/icons";
import { api } from "../lib/api";

const SERVICES = [
  { id: "ssh", name: "SSH Credential Trap", port: 2222, proto: "TCP", tactic: "Credential Access", desc: "Cowrie-style SSH banner, failed login, and command telemetry." },
  { id: "http", name: "HTTP Web Trap", port: 8080, proto: "TCP", tactic: "Initial Access", desc: "Fake admin and CVE probe surface for web exploit attempts." },
  { id: "ftp", name: "FTP Drop Trap", port: 2121, proto: "TCP", tactic: "Credential Access", desc: "Anonymous/login probe capture with path and username tagging." },
  { id: "smb", name: "SMB Share Lure", port: 4455, proto: "TCP", tactic: "Lateral Movement", desc: "File-share lure telemetry for internal discovery and auth attempts." },
  { id: "smtp", name: "SMTP Relay Trap", port: 2525, proto: "TCP", tactic: "Phishing", desc: "Mail relay, auth, HELO/EHLO, and recipient probe collection." },
];

const SERVICE_POS = {
  ssh: { left: "14%", top: "20%" },
  http: { left: "68%", top: "18%" },
  ftp: { left: "12%", top: "68%" },
  smb: { left: "70%", top: "66%" },
  smtp: { left: "43%", top: "80%" },
};

const statusColor = { active: "bg-ok", disconnected: "bg-sev-high", pending: "bg-sev-medium", never_connected: "bg-ink-3" };

export default function ThreatFeeds() {
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selectedId, setSelectedId] = useState("");
  const [enabled, setEnabled] = useState(() => Object.fromEntries(SERVICES.map(s => [s.id, true])));
  const [copied, setCopied] = useState(false);

  async function loadAgents() {
    setLoading(true);
    setError("");
    try {
      const j = await api("/api/agents");
      const list = j.agents || [];
      setAgents(list);
      setSelectedId(prev => prev || list.find(a => a.status === "active")?.id || list[0]?.id || "local");
    } catch (e) {
      setError(e.message || String(e));
      setAgents([]);
      setSelectedId("local");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadAgents(); }, []);

  const selected = agents.find(a => String(a.id) === String(selectedId)) || {
    id: "local", name: "soc-admin", ip: "100.86.115.94", status: "active", os: { name: "Ubuntu" }, group: "opxdr"
  };
  const activeServices = SERVICES.filter(s => enabled[s.id]);
  const enabledIds = activeServices.map(s => s.id).join(",");
  const downloadUrl = `/api/honeypot-agent/install.sh?agentId=${encodeURIComponent(selected.id)}&services=${encodeURIComponent(enabledIds)}`;
  const installCmd = `curl -fsSL http://100.86.115.94:8787${downloadUrl} | sudo bash`;

  const telemetryStats = useMemo(() => ({
    services: activeServices.length,
    ports: activeServices.map(s => s.port).join(", "),
    tactics: new Set(activeServices.map(s => s.tactic)).size,
    target: selected?.name || "soc-admin",
  }), [activeServices, selected]);

  function toggleService(id) {
    setEnabled(prev => ({ ...prev, [id]: !prev[id] }));
  }

  async function copyInstall() {
    await navigator.clipboard?.writeText(installCmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  }

  return (
    <div className="p-5 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-md bg-brand/20 border border-brand/40 flex items-center justify-center">
            <Network size={18} className="text-brand-accent" />
          </div>
          <div>
            <h1 className="text-xl font-extrabold text-ink-0 tracking-tight">HONEYPOT THREAT INTELLIGENCE</h1>
            <p className="text-2xs text-ink-3 mt-0.5">Deploy decoy services · collect attacker telemetry · map coverage by server</p>
          </div>
        </div>
        <button onClick={loadAgents} className="btn btn-ghost text-2xs" disabled={loading}>
          <RefreshCw size={12} className={loading ? "animate-spin" : ""} /> Refresh Inventory
        </button>
      </div>

      {error && (
        <div className="panel p-4 border-sev-medium/40">
          <div className="flex items-center gap-2 text-sev-medium text-xs"><WifiOff size={14} /> Inventory fallback active: {error}</div>
        </div>
      )}

      <div className="grid grid-cols-4 gap-4">
        <div className="stat-card"><span className="stat-label">Decoy Services</span><span className="stat-value">{telemetryStats.services}</span></div>
        <div className="stat-card"><span className="stat-label">Target Server</span><div className="text-right min-w-0"><span className="text-sm font-bold text-ink-0 truncate block max-w-36">{telemetryStats.target}</span><div className="stat-sub">inventory selected</div></div></div>
        <div className="stat-card"><span className="stat-label">Mapped Tactics</span><span className="stat-value">{telemetryStats.tactics}</span></div>
        <div className="stat-card"><span className="stat-label">Listener Ports</span><div className="text-right"><span className="text-xs font-mono text-ink-0">{telemetryStats.ports || "none"}</span><div className="stat-sub">safe high ports</div></div></div>
      </div>

      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-3 panel overflow-hidden">
          <div className="panel-header">
            <div className="panel-title">Target Server</div>
            <Server size={14} className="text-ink-3" />
          </div>
          <div className="p-3 space-y-2 max-h-[520px] overflow-y-auto">
            {loading ? <div className="text-2xs text-ink-3 font-mono">Loading inventory...</div> : null}
            {agents.length === 0 && !loading ? (
              <button onClick={() => setSelectedId("local")} className="w-full text-left border border-brand/40 bg-brand/10 rounded-md p-3">
                <div className="text-xs font-bold text-ink-0">soc-admin</div>
                <div className="text-2xs text-ink-3 font-mono">100.86.115.94 · local fallback</div>
              </button>
            ) : null}
            {agents.map(a => (
              <button key={a.id} onClick={() => setSelectedId(a.id)} className={`w-full text-left border rounded-md p-3 transition-colors ${String(selectedId) === String(a.id) ? "border-brand bg-brand/10" : "border-border hover:bg-bg-2"}`}>
                <div className="flex items-center gap-2 min-w-0">
                  <span className={`w-2 h-2 rounded-full ${statusColor[a.status] || "bg-ink-3"}`} />
                  <span className="text-xs font-bold text-ink-0 truncate">{a.name}</span>
                </div>
                <div className="text-2xs text-ink-3 font-mono mt-1">ID {a.id} · {a.ip || "no ip"}</div>
                <div className="text-3xs text-ink-3 mt-1 truncate">{a.os?.name || a.os?.platform || "unknown os"} · {a.group || "default"}</div>
              </button>
            ))}
          </div>
        </div>

        <div className="col-span-6 panel overflow-hidden">
          <div className="panel-header">
            <div>
              <div className="panel-title">Honeypot Service Map</div>
              <div className="text-2xs text-ink-3 font-mono mt-1">{selected.name} · {selected.ip || "no ip"}</div>
            </div>
            <span className="badge badge-info">{activeServices.length}/5 enabled</span>
          </div>
          <div className="relative h-[520px] bg-bg-0 overflow-hidden">
            <div className="absolute inset-6 border border-border rounded-md" />
            <div className="absolute inset-0 opacity-40" style={{ backgroundImage: "linear-gradient(#2a3150 1px, transparent 1px), linear-gradient(90deg, #2a3150 1px, transparent 1px)", backgroundSize: "34px 34px" }} />
            <div className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-36 h-36 rounded-full border border-brand/50 bg-brand/10 flex flex-col items-center justify-center text-center">
              <Server size={24} className="text-brand-accent mb-2" />
              <div className="text-xs font-extrabold text-ink-0 max-w-28 truncate">{selected.name}</div>
              <div className="text-3xs text-ink-3 font-mono max-w-28 truncate">{selected.ip || selected.id}</div>
            </div>
            {SERVICES.map(s => {
              const on = enabled[s.id];
              const pos = SERVICE_POS[s.id];
              return (
                <button key={s.id} onClick={() => toggleService(s.id)} className={`absolute w-36 border rounded-md p-2 text-left transition-all ${on ? "border-ok/50 bg-ok/10" : "border-border bg-bg-1 opacity-55"}`} style={pos}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-bold text-ink-0 truncate">{s.name}</span>
                    <span className={`w-2 h-2 rounded-full ${on ? "bg-ok" : "bg-ink-3"}`} />
                  </div>
                  <div className="text-3xs text-ink-3 font-mono mt-1">{s.proto}/{s.port}</div>
                  <div className="text-3xs text-brand-accent mt-1">{s.tactic}</div>
                </button>
              );
            })}
          </div>
        </div>

        <div className="col-span-3 panel overflow-hidden">
          <div className="panel-header">
            <div className="panel-title">Agent Download</div>
            <Download size={14} className="text-ink-3" />
          </div>
          <div className="p-4 space-y-4">
            <div className="text-xs text-ink-1">Install a lightweight OPXDR honeypot agent on the selected server. It creates safe listener services, logs probes to syslog, and labels events for SIEM dashboards.</div>
            <div className="bg-bg-0 border border-border rounded-md p-3 text-2xs font-mono text-ink-2 break-all">{installCmd}</div>
            <div className="grid grid-cols-2 gap-2">
              <button onClick={copyInstall} className="btn btn-outline text-2xs"><Copy size={12} /> {copied ? "Copied" : "Copy"}</button>
              <a href={downloadUrl} className="btn btn-brand text-2xs"><Download size={12} /> Download</a>
            </div>
            <div className="space-y-2 pt-2 border-t border-border">
              {SERVICES.map(s => (
                <label key={s.id} className="flex items-start gap-2 text-2xs cursor-pointer">
                  <input type="checkbox" checked={enabled[s.id]} onChange={() => toggleService(s.id)} className="mt-0.5" />
                  <span className="min-w-0"><span className="text-ink-1 font-semibold">{s.name}</span><span className="text-ink-3 font-mono"> · {s.proto}/{s.port}</span></span>
                </label>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-5 gap-4">
        {SERVICES.map(s => (
          <div key={s.id} className={`panel p-4 ${enabled[s.id] ? "border-ok/30" : "opacity-60"}`}>
            <div className="flex items-center justify-between mb-2">
              <Shield size={15} className={enabled[s.id] ? "text-ok" : "text-ink-4"} />
              <span className="text-3xs font-mono text-ink-3">{s.proto}/{s.port}</span>
            </div>
            <div className="text-xs font-bold text-ink-0 mb-1">{s.name}</div>
            <div className="text-3xs text-ink-3 min-h-10">{s.desc}</div>
            <div className="flex items-center gap-1.5 mt-3 text-3xs text-brand-accent"><Activity size={11} /> {s.tactic}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
