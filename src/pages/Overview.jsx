import { useContext } from "react";
import { Link } from "react-router-dom";
import { OpxdrContext } from "../App";
import { Globe, Bell, Eye, ArrowRight } from "../lib/icons";

export default function Overview() {
  const { alerts, backendStatus } = useContext(OpxdrContext);
  const critCount = alerts.filter(a => a.severity === "CRITICAL").length;
  const highCount = alerts.filter(a => a.severity === "HIGH").length;

  const cards = [
    { to: "/map",            icon: Globe,    title: "Global Threat Map",       desc: "Real-time visualization of cyber threats and attacks worldwide." },
    { to: "/alerts",         icon: Bell,     title: "Active Alerts",            desc: "Slack-style feed of all incoming alerts from Wazuh pipeline." },
    { to: "/investigations", icon: Eye,      title: "Agent Investigations",     desc: "AI-powered triage and IR recommendations for HIGH+ events." },
  ];

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <div className="mb-8">
        <h1 className="text-2xl font-extrabold text-ink-0">OPXDR Command Center</h1>
        <p className="text-sm text-ink-2 mt-1">Welcome back, SOC Analyst. {critCount} critical and {highCount} high-severity alerts require attention.</p>
      </div>

      <div className="grid grid-cols-4 gap-4 mb-8">
        <KPI label="Total Alerts (24H)"   value={alerts.length} color="text-ink-0" />
        <KPI label="Critical"             value={critCount}     color="text-sev-critical" />
        <KPI label="High"                 value={highCount}     color="text-sev-high" />
        <KPI label="Backend"              value={backendStatus === "ok" ? "Operational" : "Down"} color={backendStatus === "ok" ? "text-ok" : "text-bad"} small />
      </div>

      <div className="grid grid-cols-2 gap-4">
        {cards.map(c => {
          const Icon = c.icon;
          return (
            <Link key={c.to} to={c.to} className="panel p-5 hover:bg-bg-2 transition-colors group block">
              <div className="flex items-start gap-4">
                <div className="w-11 h-11 rounded-md bg-brand/20 border border-brand/40 flex items-center justify-center flex-shrink-0">
                  <Icon size={20} className="text-brand-accent" />
                </div>
                <div className="flex-1 min-w-0">
                  <h3 className="text-base font-bold text-ink-0 flex items-center gap-1.5">
                    {c.title}
                    <ArrowRight size={14} className="text-ink-3 group-hover:text-brand-accent group-hover:translate-x-0.5 transition" />
                  </h3>
                  <p className="text-2xs text-ink-3 mt-1.5">{c.desc}</p>
                </div>
              </div>
            </Link>
          );
        })}
      </div>
    </div>
  );
}

function KPI({ label, value, color, small }) {
  return (
    <div className="panel p-4">
      <div className="stat-label mb-1.5">{label}</div>
      <div className={`${small ? "text-base" : "text-2xl"} font-extrabold tabular-nums ${color}`}>
        {value}
      </div>
    </div>
  );
}
