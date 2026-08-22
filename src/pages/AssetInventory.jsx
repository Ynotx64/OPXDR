import { useEffect, useState } from "react";
import { Server, RefreshCw, Trash2, Search, WifiOff, Download, Copy, Shield, Activity, Database } from "../lib/icons";
import { api } from "../lib/api";

const STATUS_COLOR = { active: "bg-ok", disconnected: "bg-sev-high", pending: "bg-sev-medium", never_connected: "bg-ink-3" };
const STATUS_LABEL = { active: "Active", disconnected: "Disconnected", pending: "Pending", never_connected: "Never Connected" };
const SIEM_TELEMETRY = [
  { id: "system", label: "System Inventory", detail: "host, OS, uptime" },
  { id: "process", label: "Process Telemetry", detail: "process snapshots" },
  { id: "network", label: "Network Telemetry", detail: "listening ports" },
  { id: "auth", label: "Auth Telemetry", detail: "login signals" },
  { id: "file", label: "File Integrity", detail: "watched paths" },
];

export default function AssetInventory() {
  const [agents, setAgents] = useState([]);
  const [summary, setSummary] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState("");
  const [actionLoading, setActionLoading] = useState(null);
  const [selectedAgentId, setSelectedAgentId] = useState("000");
  const [customAgentId, setCustomAgentId] = useState("");
  const [customAgentName, setCustomAgentName] = useState("");
  const [copied, setCopied] = useState(false);

  async function loadAgents() {
    setLoading(true);
    setError(null);
    try {
      const data = await api("/api/agents");
      setAgents(data.agents || []);
      setSummary(data.status_summary || {});
    } catch (e) {
      setError(e.message);
    }
    setLoading(false);
  }

  useEffect(() => { loadAgents(); }, []);

  useEffect(() => {
    if (selectedAgentId === "__custom__") return;
    if (agents.length && !agents.some(a => String(a.id) === String(selectedAgentId))) {
      setSelectedAgentId(String(agents[0].id));
    }
  }, [agents, selectedAgentId]);

  async function restartAgent(id) {
    setActionLoading(`restart-${id}`);
    try {
      await api(`/api/agents/${id}/restart`, { method: "PUT" });
    } catch (e) {
      alert(`Restart failed: ${e.message}`);
    }
    setActionLoading(null);
  }

  async function removeAgent(id) {
    if (!confirm(`Remove agent ${id} from Wazuh?`)) return;
    setActionLoading(`remove-${id}`);
    try {
      await api(`/api/agents/${id}`, { method: "DELETE" });
      setAgents(prev => prev.filter(a => a.id !== id));
    } catch (e) {
      alert(`Remove failed: ${e.message}`);
    }
    setActionLoading(null);
  }

  const filtered = agents.filter(a =>
    !search || a.name.toLowerCase().includes(search.toLowerCase()) || a.ip?.includes(search) || String(a.id).includes(search)
  );

  const counts = { active: 0, disconnected: 0, pending: 0, never_connected: 0 };
  agents.forEach(a => { counts[a.status] = (counts[a.status] || 0) + 1; });
  const customMode = selectedAgentId === "__custom__";
  const selectedAgent = customMode
    ? { id: customAgentId.trim() || "chicago-001", name: customAgentName.trim() || "Chicago Server", ip: "external" }
    : agents.find(a => String(a.id) === String(selectedAgentId)) || agents[0] || { id: "000", name: "soc-admin" };
  const backendOrigin = typeof window !== "undefined" ? window.location.origin.replace(/:5173$/, ":8787") : "http://100.86.115.94:8787";
  const installerPath = `/api/opxdr-siem-agent/install.sh?agentId=${encodeURIComponent(selectedAgent?.id || "000")}&name=${encodeURIComponent(selectedAgent?.name || "OPXDR Agent")}`;
  const installerUrl = `${backendOrigin}${installerPath}`;
  const installCommand = `curl -fsSL ${installerUrl} | sudo bash`;

  async function copyInstallCommand() {
    try {
      await navigator.clipboard.writeText(installCommand);
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    } catch {
      alert("Copy failed. Select the command text and copy it manually.");
    }
  }

  function validDate(value) {
    const date = new Date(value);
    if (!Number.isFinite(date.getTime()) || date.getFullYear() > 2100) return null;
    return date;
  }

  return (
    <div className="p-5 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-md bg-brand/20 border border-brand/40 flex items-center justify-center">
            <Server size={18} className="text-brand-accent" />
          </div>
          <div>
            <h1 className="text-xl font-extrabold text-ink-0 tracking-tight">ASSET INVENTORY</h1>
            <p className="text-2xs text-ink-3 mt-0.5">Wazuh agents · endpoints · network devices</p>
          </div>
        </div>
        <button onClick={loadAgents} className="btn btn-ghost text-2xs" disabled={loading}>
          <RefreshCw size={12} className={loading ? "animate-spin" : ""} /> Refresh
        </button>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-5 gap-4">
        <div className="stat-card"><span className="stat-label">Total Agents</span><span className="stat-value">{agents.length}</span></div>
        <div className="stat-card"><span className="stat-label">Active</span><div className="flex items-center gap-2 mt-0.5"><span className="w-2 h-2 rounded-full bg-ok" /><span className="stat-value">{counts.active || 0}</span></div></div>
        <div className="stat-card"><span className="stat-label">Disconnected</span><div className="flex items-center gap-2 mt-0.5"><span className="w-2 h-2 rounded-full bg-sev-high" /><span className="stat-value text-sev-high">{counts.disconnected || 0}</span></div></div>
        <div className="stat-card"><span className="stat-label">Pending</span><div className="flex items-center gap-2 mt-0.5"><span className="w-2 h-2 rounded-full bg-sev-medium" /><span className="stat-value text-sev-medium">{counts.pending || 0}</span></div></div>
        <div className="stat-card"><span className="stat-label">Never Connected</span><div className="flex items-center gap-2 mt-0.5"><span className="w-2 h-2 rounded-full bg-ink-3" /><span className="stat-value text-ink-3">{counts.never_connected || 0}</span></div></div>
      </div>

      <div className="panel p-4 border-brand/30">
        <div className="grid grid-cols-[1fr_auto] gap-4 items-start">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded bg-brand/15 border border-brand/35 flex items-center justify-center">
                <Shield size={15} className="text-brand-accent" />
              </div>
              <div>
                <div className="text-sm font-extrabold text-ink-0">OPXDR SIEM Agent Download</div>
                <div className="text-2xs text-ink-3">Custom endpoint telemetry agent for Detection Registry rules and SIEM dashboards</div>
              </div>
            </div>

            <div className="grid grid-cols-[220px_1fr] gap-3 mt-4">
              <label className="space-y-1">
                <span className="text-3xs uppercase tracking-widest text-ink-3 font-bold">Selected Server</span>
                <select
                  value={String(selectedAgentId)}
                  onChange={e => setSelectedAgentId(e.target.value)}
                  className="w-full bg-bg-1 border border-border rounded px-3 py-2 text-xs text-ink-0 outline-none focus:border-brand"
                >
                  {agents.length ? agents.map(a => (
                    <option key={a.id} value={a.id}>{a.name} · ID {a.id}</option>
                  )) : <option value="000">soc-admin · ID 000</option>}
                  <option value="__custom__">External / custom server</option>
                </select>
              </label>
              <div className="space-y-1 min-w-0">
                <span className="text-3xs uppercase tracking-widest text-ink-3 font-bold">Install Command</span>
                <div className="flex items-stretch gap-2">
                  <code className="flex-1 min-w-0 bg-bg-0 border border-border rounded px-3 py-2 text-2xs text-ink-1 font-mono overflow-x-auto whitespace-nowrap">
                    {installCommand}
                  </code>
                  <button onClick={copyInstallCommand} className="btn btn-outline text-2xs w-24" title="Copy install command">
                    <Copy size={12} /> {copied ? "Copied" : "Copy"}
                  </button>
                  <a href={installerUrl} className="btn btn-primary text-2xs w-28 justify-center" title="Download SIEM agent installer">
                    <Download size={12} /> Download
                  </a>
                </div>
              </div>
            </div>

            {customMode && (
              <div className="grid grid-cols-2 gap-3 mt-3">
                <label className="space-y-1">
                  <span className="text-3xs uppercase tracking-widest text-ink-3 font-bold">Custom Agent ID</span>
                  <input
                    value={customAgentId}
                    onChange={e => setCustomAgentId(e.target.value)}
                    placeholder="chicago-001"
                    className="w-full bg-bg-1 border border-border rounded px-3 py-2 text-xs text-ink-0 outline-none focus:border-brand"
                  />
                </label>
                <label className="space-y-1">
                  <span className="text-3xs uppercase tracking-widest text-ink-3 font-bold">Custom Server Name</span>
                  <input
                    value={customAgentName}
                    onChange={e => setCustomAgentName(e.target.value)}
                    placeholder="Chicago Web Server"
                    className="w-full bg-bg-1 border border-border rounded px-3 py-2 text-xs text-ink-0 outline-none focus:border-brand"
                  />
                </label>
              </div>
            )}

            <div className="grid grid-cols-5 gap-2 mt-4">
              {SIEM_TELEMETRY.map(s => (
                <div key={s.id} className="bg-bg-1 border border-border rounded px-2.5 py-2">
                  <div className="flex items-center gap-1.5 text-2xs text-ink-0 font-bold">
                    {s.id === "file" ? <Database size={11} className="text-brand-accent" /> : <Activity size={11} className="text-brand-accent" />}
                    {s.label}
                  </div>
                  <div className="text-3xs text-ink-3 font-mono mt-1">{s.detail}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="w-44 bg-bg-1 border border-border rounded p-3">
            <div className="text-3xs uppercase tracking-widest text-ink-3 font-bold">Target</div>
            <div className="text-sm font-bold text-ink-0 mt-1 truncate">{selectedAgent?.name || "soc-admin"}</div>
            <div className="text-2xs text-ink-3 font-mono mt-1">ID {selectedAgent?.id || "000"}</div>
            <div className="text-2xs text-ink-2 font-mono mt-2 truncate">{selectedAgent?.ip || "127.0.0.1"}</div>
          </div>
        </div>
      </div>

      {/* Search */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-xs">
          <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-ink-3" />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search by name, IP, or ID..."
            className="w-full bg-bg-1 border border-border rounded pl-7 pr-3 py-1.5 text-xs text-ink-0 outline-none focus:border-brand"
          />
        </div>
        {search && <span className="text-2xs text-ink-3 font-mono">{filtered.length} of {agents.length}</span>}
      </div>

      {/* Error */}
      {error && (
        <div className="panel p-4 border-sev-critical/40">
          <div className="flex items-center gap-2 text-sev-critical text-xs">
            <WifiOff size={14} /> Failed to load agents: {error}
          </div>
          <div className="text-2xs text-ink-3 mt-1">Ensure Wazuh API is configured in .env (WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASS)</div>
        </div>
      )}

      {/* Loading */}
      {loading && !error && (
        <div className="grid grid-cols-3 gap-4">
          {[1,2,3,4,5,6].map(i => (
            <div key={i} className="panel p-4 animate-pulse">
              <div className="h-4 bg-bg-2 rounded w-2/3 mb-3" />
              <div className="h-3 bg-bg-2 rounded w-1/2 mb-2" />
              <div className="h-3 bg-bg-2 rounded w-3/4 mb-2" />
              <div className="h-3 bg-bg-2 rounded w-1/3" />
            </div>
          ))}
        </div>
      )}

      {/* Agent cards */}
      {!loading && !error && (
        <div className="grid grid-cols-3 gap-4">
          {filtered.map(a => (
            <div key={a.id} className="panel">
              <div className="p-4">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-2.5 min-w-0">
                    <span className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${STATUS_COLOR[a.status] || "bg-ink-3"}`} />
                    <div className="min-w-0">
                      <div className="text-sm font-bold text-ink-0 truncate">{a.name}</div>
                      <div className="text-2xs text-ink-3 font-mono">ID: {a.id}</div>
                    </div>
                  </div>
                  <span className={`text-3xs font-mono uppercase px-1.5 py-0.5 rounded flex-shrink-0 ${
                    a.status === "active" ? "bg-ok/10 text-ok border border-ok/30"
                    : a.status === "disconnected" ? "bg-sev-high/10 text-sev-high border border-sev-high/30"
                    : "bg-ink-2/10 text-ink-2 border border-ink-2/30"
                  }`}>{STATUS_LABEL[a.status] || a.status}</span>
                </div>

                <div className="space-y-1.5 text-2xs font-mono">
                  <div className="flex items-center gap-2">
                    <span className="text-ink-3 w-12">IP:</span>
                    <span className="text-ink-0">{a.ip || "—"}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-ink-3 w-12">OS:</span>
                    <span className="text-ink-0 truncate">{a.os?.name || a.os?.platform || "—"} {a.os?.version || ""}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-ink-3 w-12">Group:</span>
                    <span className="text-brand-accent">{a.group || "default"}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-ink-3 w-12">Wazuh:</span>
                    <span className="text-ink-2">{a.version || "—"}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-ink-3 w-12">OPXDR:</span>
                    <span className={a.opxdrAgent?.installed ? "text-ok" : "text-ink-3"}>
                      {a.opxdrAgent?.installed ? a.opxdrAgent.version : "not installed"}
                    </span>
                  </div>
                  {a.opxdrAgent?.installed && (
                    <div className="grid grid-cols-3 gap-1 text-3xs">
                      <span className="bg-bg-1 border border-border rounded px-1.5 py-1 text-ink-2">Ports {a.opxdrAgent.activePorts ?? 0}</span>
                      <span className="bg-bg-1 border border-border rounded px-1.5 py-1 text-ink-2">Proc {a.opxdrAgent.processCount ?? 0}</span>
                      <span className="bg-bg-1 border border-border rounded px-1.5 py-1 text-ink-2">Auth {a.opxdrAgent.authEvents ?? 0}</span>
                    </div>
                  )}
                  {(a.opxdrAgent?.lastSeen || validDate(a.lastKeepAlive)) && (
                    <div className="flex items-center gap-2">
                      <span className="text-ink-3 w-12">Last Seen:</span>
                      <span className="text-ink-2">
                        {new Date(a.opxdrAgent?.lastSeen || validDate(a.lastKeepAlive)).toLocaleString()}
                      </span>
                    </div>
                  )}
                </div>

                <div className="flex items-center gap-1.5 mt-4 pt-3 border-t border-border">
                  <button
                    onClick={() => restartAgent(a.id)}
                    disabled={actionLoading === `restart-${a.id}`}
                    className="btn btn-outline text-2xs flex-1"
                  ><RefreshCw size={11} className={actionLoading === `restart-${a.id}` ? "animate-spin" : ""} /> Restart</button>
                  <button
                    onClick={() => removeAgent(a.id)}
                    disabled={actionLoading === `remove-${a.id}`}
                    className="btn btn-ghost text-2xs text-sev-critical"
                  ><Trash2 size={11} /> Remove</button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {!loading && !error && filtered.length === 0 && (
        <div className="panel p-8 text-center text-2xs text-ink-3">
          {search ? `No agents matching "${search}"` : "No agents found. Ensure Wazuh API is configured and has registered agents."}
        </div>
      )}
    </div>
  );
}
