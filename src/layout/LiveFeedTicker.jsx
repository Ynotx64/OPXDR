import { useEffect, useState } from "react";
import { timeAgo } from "../lib/api";

export default function LiveFeedTicker({ alerts = [] }) {
  // Take 12 latest, severity-colored
  const latest = alerts.slice(0, 12);

  return (
    <div className="h-[36px] bg-bg-1 border-t border-border flex items-center px-5 gap-4 flex-shrink-0 overflow-hidden">
      <div className="flex items-center gap-2 flex-shrink-0">
        <span className="live-dot" />
        <span className="text-2xs font-semibold uppercase tracking-[0.18em] text-ink-1">Live Feed</span>
      </div>
      <div className="w-px h-5 bg-border flex-shrink-0" />

      {latest.length === 0 ? (
        <div className="text-2xs text-ink-3">Waiting for live alerts from Wazuh pipeline...</div>
      ) : (
        <div className="flex items-center gap-6 overflow-hidden whitespace-nowrap flex-1">
          {latest.map((a) => {
            const sev = (a.severity || "MEDIUM").toUpperCase();
            const sevColor =
              sev === "CRITICAL" ? "text-sev-critical" :
              sev === "HIGH" ? "text-sev-high" :
              sev === "MEDIUM" ? "text-sev-medium" :
              "text-sev-low";
            return (
              <div key={a.id} className="flex items-center gap-2 text-2xs flex-shrink-0">
                <span className={`${sevColor} text-base leading-none`}>●</span>
                <span className="text-ink-3 font-mono">{timeAgo(a.time)}</span>
                <span className="text-ink-1 truncate max-w-[420px]">{a.ruleName}</span>
                {a.host && a.host !== "—" && (
                  <span className="text-ink-3 font-mono">@ {a.host}</span>
                )}
              </div>
            );
          })}
        </div>
      )}

      <div className="ml-auto text-2xs text-ink-3 flex-shrink-0">
        Auto-refresh: <span className="text-ink-1 font-mono">5s</span>
      </div>
    </div>
  );
}
