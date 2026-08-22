import { useContext, useEffect, useState } from "react";
import { OpxdrContext } from "../App";
import { Settings as SettingsIcon, RefreshCw, CheckCircle2, Circle } from "../lib/icons";
import { api } from "../lib/api";

export default function Settings() {
  const { backendStatus } = useContext(OpxdrContext);
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(false);

  async function loadHealth() {
    setLoading(true);
    try {
      const j = await api("/api/health");
      setHealth(j);
    } catch (e) {
      setHealth({ error: e.message });
    }
    setLoading(false);
  }

  useEffect(() => { loadHealth(); }, []);

  return (
    <div className="p-5 max-w-4xl">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-xl font-extrabold text-ink-0 flex items-center gap-2">
            <SettingsIcon size={20} className="text-brand-accent" /> Settings
          </h1>
          <p className="text-2xs text-ink-3 mt-0.5">Backend health, AI providers, integrations</p>
        </div>
        <button onClick={loadHealth} disabled={loading} className="btn btn-outline">
          <RefreshCw size={14} className={loading ? "animate-spin" : ""} /> Refresh
        </button>
      </div>

      <div className="panel mb-4">
        <div className="panel-header">
          <span className="panel-title">Backend Status</span>
          <span className="flex items-center gap-1.5">
            {backendStatus === "ok" ? (
              <><CheckCircle2 size={14} className="text-ok" /><span className="text-2xs text-ok font-mono">Operational</span></>
            ) : (
              <><Circle size={14} className="text-bad" /><span className="text-2xs text-bad font-mono">Down</span></>
            )}
          </span>
        </div>
        {health && (
          <div className="p-4 grid grid-cols-2 gap-x-6 gap-y-2 text-xs font-mono">
            <Row k="Wazuh" v={health.wazuh || "—"} ok={health.wazuh === "ok"} />
            <Row k="Indexer" v={health.indexer || "—"} ok={health.indexer === "ok"} />
            <Row k="AI Provider" v={health.ai_provider || "none"} ok={health.ai_provider && health.ai_provider !== "none"} />
            <Row k="Slack" v={health.slack_enabled ? "enabled" : "disabled"} ok={health.slack_enabled} />
            <Row k="Alert Source" v={health.alert_source || "—"} />
            <Row k="Rules Root" v={health.rules_root || "—"} />
          </div>
        )}
      </div>

      <div className="panel mb-4">
        <div className="panel-header">
          <span className="panel-title">AI Auto-Report</span>
        </div>
        <div className="p-4 text-xs text-ink-2">
          {health?.ai_auto_report ? (
            <>Auto-investigation enabled for alerts at level <span className="text-ok font-mono">{health.ai_auto_report_min_level}+</span>. Critical and high-severity Wazuh events will trigger a streaming agent investigation on arrival.</>
          ) : (
            <>Auto-investigation is disabled. Set <code className="bg-bg-2 px-1.5 py-0.5 rounded text-brand-accent">AI_AUTO_REPORT=true</code> in <code className="bg-bg-2 px-1.5 py-0.5 rounded text-brand-accent">.env</code> to enable.</>
          )}
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">Environment</span>
        </div>
        <div className="p-4 text-xs text-ink-2 space-y-1.5">
          <div><span className="text-ink-3">Vite dev:</span> <code className="text-brand-accent font-mono">5173</code></div>
          <div><span className="text-ink-3">Backend:</span> <code className="text-brand-accent font-mono">8787</code></div>
          <div><span className="text-ink-3">Indexer:</span> <code className="text-brand-accent font-mono">{health?.indexer_url || "—"}</code></div>
          <div><span className="text-ink-3">Index pattern:</span> <code className="text-brand-accent font-mono">{health?.indexer_index || "—"}</code></div>
        </div>
      </div>
    </div>
  );
}

function Row({ k, v, ok }) {
  return (
    <>
      <span className="text-ink-3">{k}:</span>
      <span className={ok === true ? "text-ok" : ok === false ? "text-bad" : "text-ink-1"}>{v}</span>
    </>
  );
}
