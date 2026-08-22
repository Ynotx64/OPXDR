import { useContext, useState } from "react";
import { OpxdrContext } from "../App";
import { Bell, RefreshCw, Eye, Save, AlertTriangle } from "../lib/icons";
import { timeAgo, SEV_HEX } from "../lib/api";
import { useNavigate } from "react-router-dom";

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2 };

export default function ActiveAlerts() {
  const { alerts, refreshAlerts, refreshingAlerts, savedDocs, setSavedDocs } = useContext(OpxdrContext);
  const [filter, setFilter] = useState("ALL");
  const [lastRefreshed, setLastRefreshed] = useState(null);
  const navigate = useNavigate();

  async function handleRefresh() {
    await refreshAlerts();
    setLastRefreshed(new Date());
  }

  function saveAlert(a) {
    const doc = {
      id: `ALERT-${Date.now()}`,
      title: `Alert: ${a.ruleName}`,
      alert: a,
      created: new Date().toISOString(),
      report: [
        `# Alert: ${a.ruleName}`,
        ``,
        `| Field | Value |`,
        `|---|---|`,
        `| ID | \`${a.id}\` |`,
        `| Rule | ${a.ruleName} |`,
        `| Severity | ${a.severity} (level ${a.level}) |`,
        `| Tactic | ${a.tactic} |`,
        `| MITRE | ${a.mitre} |`,
        `| Host | \`${a.host}\` |`,
        `| Src IP | \`${a.srcIp}\` |`,
        `| Dst IP | \`${a.dstIp}\` |`,
        `| Account | \`${a.account}\` |`,
        `| Time | ${a.time} |`,
        `| IOCs | ${(a.iocs || []).map(i => `[${i.t}] ${i.v}`).join(", ") || "—"} |`,
      ].join("\n"),
    };
    setSavedDocs([doc, ...savedDocs]);
  }

  const filtered = alerts
    .filter(a => filter === "ALL" || a.severity === filter)
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));

  const counts = {
    CRITICAL: alerts.filter(a => a.severity === "CRITICAL").length,
    HIGH:     alerts.filter(a => a.severity === "HIGH").length,
    MEDIUM:   alerts.filter(a => a.severity === "MEDIUM").length,
  };

  return (
    <div className="p-5">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-extrabold text-ink-0">Active Alerts</h1>
          <p className="text-2xs text-ink-3 mt-0.5">
            Medium–Critical alerts from Wazuh · {alerts.length} total
            {lastRefreshed && (
              <span className="ml-2 text-ink-4">
                · refreshed at {lastRefreshed.toLocaleTimeString()} · last 24h
              </span>
            )}
          </p>
        </div>
        <button
          onClick={handleRefresh}
          disabled={refreshingAlerts}
          className="btn btn-ghost disabled:opacity-50"
          title="Reload last 24 hours of alerts"
        >
          <RefreshCw size={14} className={refreshingAlerts ? "animate-spin" : ""} />
          {refreshingAlerts ? "Refreshing…" : "Refresh 24h"}
        </button>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-3 gap-3 mb-4">
        {["CRITICAL", "HIGH", "MEDIUM"].map((s) => (
          <button
            key={s}
            onClick={() => setFilter(filter === s ? "ALL" : s)}
            className={`panel p-3 text-left transition-colors ${filter === s ? "border-brand bg-bg-2" : "hover:bg-bg-2"}`}
          >
            <div className="stat-label">{s}</div>
            <div className="text-xl font-extrabold tabular-nums mt-0.5" style={{ color: SEV_HEX[s] }}>
              {counts[s]}
            </div>
          </button>
        ))}
      </div>

      {/* Feed */}
      <div className="panel">
        <div className="panel-header">
          <div className="flex items-center gap-2">
            <span className="live-dot" />
            <span className="panel-title">Live Alert Feed</span>
            <span className="text-2xs text-ink-3">— {filtered.length} {filter !== "ALL" && `${filter} `}alerts</span>
          </div>
          {filter !== "ALL" && (
            <button onClick={() => setFilter("ALL")} className="text-2xs text-ink-3 hover:text-ink-0">
              Clear filter
            </button>
          )}
        </div>

        <div className="divide-y divide-border">
          {filtered.length === 0 && (
            <div className="p-12 text-center text-ink-3 text-sm">
              <Bell size={32} className="mx-auto mb-3 opacity-40" />
              No alerts matching filter.
            </div>
          )}
          {filtered.map((a) => (
            <AlertRow key={a.id} alert={a} onInvestigate={() => navigate(`/investigations?alert=${a.id}`)} onSave={() => saveAlert(a)} />
          ))}
        </div>
      </div>
    </div>
  );
}

function AlertRow({ alert: a, onInvestigate, onSave }) {
  const [saved, setSaved] = useState(false);
  const sevC = a.severity === "CRITICAL" ? "sev-critical"
    : a.severity === "HIGH" ? "sev-high"
    : a.severity === "MEDIUM" ? "sev-medium"
    : "sev-low";

  return (
    <div className="p-4 hover:bg-bg-2 transition-colors">
      <div className="flex items-start gap-3">
        <div className={`w-1 self-stretch rounded-full bg-${sevC} flex-shrink-0`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1.5 flex-wrap">
            <AlertTriangle size={14} className={`text-${sevC} flex-shrink-0`} />
            <span className="text-sm font-bold text-ink-0">{a.ruleName}</span>
            <span className={`badge badge-${a.severity === "CRITICAL" ? "critical" : a.severity === "HIGH" ? "high" : a.severity === "MEDIUM" ? "medium" : "low"}`}>
              {a.severity}
            </span>
            <span className="text-3xs font-mono text-ink-3">{a.id}</span>
            <span className="text-3xs font-mono text-ink-3 ml-auto">{timeAgo(a.time)}</span>
          </div>

          {/* Field grid */}
          <div className="grid grid-cols-3 gap-2 my-2">
            {[
              { k: "host", v: a.host },
              { k: "src_ip", v: a.srcIp },
              { k: "account", v: a.account },
            ].filter(({ v }) => v && v !== "—").map(({ k, v }) => (
              <div key={k} className="bg-bg-2 border border-border rounded px-2 py-1">
                <div className="text-3xs text-ink-3 uppercase tracking-wider">{k}</div>
                <div className="text-2xs font-mono text-ink-0 truncate">{v}</div>
              </div>
            ))}
          </div>

          {/* IOCs */}
          {a.iocs?.length > 0 && (
            <div className="flex gap-1.5 flex-wrap mb-2">
              {a.iocs.slice(0, 5).map((ioc, i) => (
                <span key={i} className="badge badge-medium">
                  [{ioc.t}] {ioc.v}
                </span>
              ))}
            </div>
          )}

          {/* Actions */}
          <div className="flex gap-2 mt-2">
            <button
              onClick={onInvestigate}
              className="btn btn-outline gap-1.5 text-2xs"
            >
              <Eye size={12} /> Investigate
            </button>
            <button
              onClick={() => { onSave(); setSaved(true); }}
              disabled={saved}
              className="btn btn-ghost gap-1.5 text-2xs disabled:opacity-40"
            >
              <Save size={12} /> {saved ? "Saved" : "Save to Reports"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
