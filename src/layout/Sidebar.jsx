import { NavLink } from "react-router-dom";
import {
  Zap, Globe, Shield, Bell, BookOpen, Eye, Network,
  Box, Layers, Workflow, PlayCircle, Settings, FileText,
  Server, BarChart3, Power, Lock
} from "../lib/icons";

const NAV_SECTIONS = [
  {
    section: "Overview",
    items: [
      { to: "/",         label: "Overview",         icon: BarChart3 },
      { to: "/map",      label: "Global Map",       icon: Globe },
    ],
  },
  {
    section: "Detection",
    items: [
      { to: "/registry",      label: "Detection Registry", icon: BookOpen },
      { to: "/alerts",        label: "Active Alerts",      icon: Bell,    badge: "live" },
      { to: "/investigations",label: "Agent Investigations", icon: Eye },

    ],
  },
  {
    section: "Intelligence",
    items: [
      { to: "/feeds",    label: "Honeypot Intel",   icon: Network },
      { to: "/iocs",     label: "Indicators",     icon: Box },
      { to: "/patterns", label: "Attack Patterns",icon: Layers },
    ],
  },
  {
    section: "Assets",
    items: [
      { to: "/assets",    label: "Asset Inventory",icon: Server },
      { to: "/network",   label: "Network Map",    icon: Network },
      { to: "/vulns",     label: "Vulnerabilities",icon: Lock },
    ],
  },
  {
    section: "Automation",
    items: [
      { to: "/playbooks", label: "Playbooks",       icon: Workflow },
      { to: "/responses", label: "Response Actions",icon: PlayCircle },
      { to: "/integrations", label: "Integrations", icon: Network },
      { to: "/tor",       label: "Tor Monitor",     icon: Eye, accent: true },
    ],
  },
  {
    section: "Admin",
    items: [
      { to: "/reports",  label: "Reports",  icon: FileText },
      { to: "/settings", label: "Settings", icon: Settings },
    ],
  },
];

export default function Sidebar({ alertCount = 0 }) {
  return (
    <aside className="w-[230px] h-full bg-bg-1 border-r border-border flex flex-col flex-shrink-0">
      {/* Logo block */}
      <div className="h-[60px] flex items-center gap-2.5 px-4 border-b border-border flex-shrink-0">
        <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-brand to-brand-accent flex items-center justify-center shadow-glow text-brand">
          <Zap size={18} className="text-white" />
        </div>
        <div>
          <div className="text-[15px] font-extrabold tracking-[0.15em] text-ink-0">OPXDR</div>
          <div className="text-3xs uppercase tracking-[0.18em] text-ink-3">Geo</div>
        </div>
      </div>

      {/* Nav scroll */}
      <nav className="flex-1 overflow-y-auto py-2 pb-4">
        {NAV_SECTIONS.map((sec) => (
          <div key={sec.section}>
            <div className="nav-section">{sec.section}</div>
            <div className="px-2 space-y-0.5">
              {sec.items.map((it) => {
                const Icon = it.icon;
                const isBell = it.label === "Active Alerts";
                return (
                  <NavLink
                    key={it.to}
                    to={it.to}
                    end={it.to === "/"}
                    className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
                  >
                    <Icon size={16} className="flex-shrink-0" />
                    <span className="flex-1 truncate">{it.label}</span>
                    {isBell && alertCount > 0 && (
                      <span className="bg-sev-high text-white text-3xs font-bold font-mono px-1.5 py-0.5 rounded">
                        {alertCount > 99 ? "99+" : alertCount}
                      </span>
                    )}
                  </NavLink>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* User block */}
      <div className="border-t border-border p-3 flex-shrink-0">
        <div className="flex items-center gap-2.5 p-2 rounded-md hover:bg-bg-2 cursor-pointer">
          <div className="w-8 h-8 rounded-md bg-bg-3 border border-border flex items-center justify-center text-ink-2 text-xs font-semibold">SO</div>
          <div className="flex-1 min-w-0">
            <div className="text-xs font-semibold text-ink-0">SOC Analyst</div>
            <div className="text-3xs text-ink-3">Tier 1 Analyst</div>
          </div>
        </div>
        <div className="flex items-center gap-1.5 mt-1 px-2 text-3xs text-ink-3">
          <span className="live-dot" />
          <span className="uppercase tracking-wider font-mono">Online</span>
        </div>
      </div>
    </aside>
  );
}
