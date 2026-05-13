import React from "react";

const NAV_SECTIONS = [
  {
    title: "OVERVIEW",
    items: [
      { id: "global-map", label: "Global Map", icon: "globe" },
    ],
  },
  {
    title: "DETECTION",
    items: [
      { id: "registry", label: "Detection Registry", icon: "shield" },
      { id: "slack", label: "Active Alerts", icon: "alert", badgeColor: "#ef4444" },
      { id: "agent", label: "Agent Investigations", icon: "search" },
    ],
  },
  {
    title: "INTELLIGENCE",
    items: [
      { id: "geointel", label: "Geo Intel", icon: "map" },
    ],
  },
  {
    title: "ADMIN",
    items: [
      { id: "documents", label: "Documents", icon: "file" },
    ],
  },
];

function Icon({ name, size = 16, color = "currentColor" }) {
  const icons = {
    globe: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5">
        <circle cx="12" cy="12" r="10" />
        <line x1="2" y1="12" x2="22" y2="12" />
        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
      </svg>
    ),
    shield: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    ),
    alert: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
        <line x1="12" y1="9" x2="12" y2="13" />
        <line x1="12" y1="17" x2="12.01" y2="17" />
      </svg>
    ),
    search: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5">
        <circle cx="11" cy="11" r="8" />
        <line x1="21" y1="21" x2="16.65" y2="16.65" />
      </svg>
    ),
    map: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5">
        <polygon points="1 6 1 22 8 18 16 22 23 18 23 2 16 6 8 2 1 6" />
        <line x1="8" y1="2" x2="8" y2="18" />
        <line x1="16" y1="6" x2="16" y2="22" />
      </svg>
    ),
    file: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="16" y1="13" x2="8" y2="13" />
        <line x1="16" y1="17" x2="8" y2="17" />
        <polyline points="10 9 9 9 8 9" />
      </svg>
    ),
    zap: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2">
        <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
      </svg>
    ),
    user: (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5">
        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
        <circle cx="12" cy="7" r="4" />
      </svg>
    ),
  };
  return icons[name] || null;
}

export default function Sidebar({
  activeNav,
  onNavChange,
  collapsed = false,
  alertCounts = {},
  torEnabled = false,
}) {
  return (
    <div
      style={{
        width: collapsed ? 56 : 220,
        minWidth: collapsed ? 56 : 220,
        height: "100%",
        background: "#060a12",
        borderRight: "1px solid #1a2332",
        display: "flex",
        flexDirection: "column",
        transition: "width 0.2s ease, min-width 0.2s ease",
        overflow: "hidden",
      }}
    >
      {/* Logo */}
      <div
        style={{
          padding: collapsed ? "16px 12px" : "16px 16px",
          borderBottom: "1px solid #1a2332",
          display: "flex",
          alignItems: "center",
          gap: 10,
        }}
      >
        <div
          style={{
            width: 32,
            height: 32,
            background: "linear-gradient(135deg, #0ea5e9, #38bdf8)",
            borderRadius: 8,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
          }}
        >
          <Icon name="zap" size={18} color="#000" />
        </div>
        {!collapsed && (
          <div>
            <div
              style={{
                fontFamily: "'Oxanium', sans-serif",
                fontWeight: 800,
                fontSize: "0.95rem",
                letterSpacing: 2,
                color: "#f1f5f9",
              }}
            >
              OPXDR GEO
            </div>
          </div>
        )}
      </div>

      {/* Navigation */}
      <div
        style={{
          flex: 1,
          overflow: "auto",
          padding: "8px 0",
        }}
      >
        {NAV_SECTIONS.map((section) => (
          <div key={section.title} style={{ marginBottom: 8 }}>
            {!collapsed && (
              <div
                style={{
                  padding: "8px 16px 4px",
                  fontSize: "0.6rem",
                  fontFamily: "monospace",
                  color: "#475569",
                  letterSpacing: 1,
                  fontWeight: 600,
                }}
              >
                {section.title}
              </div>
            )}
            {section.items.map((item) => {
              const isActive = activeNav === item.id;
              const badge = alertCounts[item.id] || null;

              return (
                <button
                  key={item.id}
                  onClick={() => onNavChange(item.id)}
                  style={{
                    width: "100%",
                    display: "flex",
                    alignItems: "center",
                    gap: 10,
                    padding: collapsed ? "10px 16px" : "8px 16px",
                    background: isActive ? "#0ea5e920" : "transparent",
                    border: "none",
                    borderLeft: isActive ? "2px solid #0ea5e9" : "2px solid transparent",
                    color: isActive ? "#0ea5e9" : "#64748b",
                    cursor: "pointer",
                    fontSize: "0.75rem",
                    fontFamily: "'Inter', sans-serif",
                    textAlign: "left",
                    transition: "all 0.15s ease",
                  }}
                  onMouseEnter={(e) => {
                    if (!isActive) {
                      e.currentTarget.style.background = "#0a1525";
                      e.currentTarget.style.color = "#94a3b8";
                    }
                  }}
                  onMouseLeave={(e) => {
                    if (!isActive) {
                      e.currentTarget.style.background = "transparent";
                      e.currentTarget.style.color = "#64748b";
                    }
                  }}
                >
                  <Icon name={item.icon} size={16} color="currentColor" />
                  {!collapsed && (
                    <>
                      <span style={{ flex: 1 }}>{item.label}</span>
                      {badge && (
                        <span
                          style={{
                            background: item.badgeColor || "#0ea5e9",
                            color: "#fff",
                            fontSize: "0.6rem",
                            fontWeight: 700,
                            padding: "2px 6px",
                            borderRadius: 10,
                            minWidth: 18,
                            textAlign: "center",
                          }}
                        >
                          {badge}
                        </span>
                      )}
                    </>
                  )}
                </button>
              );
            })}
          </div>
        ))}

        {/* Tor Monitor - Special Item */}
        {!collapsed && (
          <div style={{ marginTop: 8, padding: "0 8px" }}>
            <button
              onClick={() => onNavChange("tormon")}
              style={{
                width: "100%",
                display: "flex",
                alignItems: "center",
                gap: 10,
                padding: "10px 12px",
                background: activeNav === "tormon" ? "#00ff8c15" : "#0a1525",
                border: activeNav === "tormon" ? "1px solid #00ff8c40" : "1px solid #1a2332",
                borderRadius: 8,
                color: activeNav === "tormon" ? "#00ff8c" : "#64748b",
                cursor: "pointer",
                fontSize: "0.75rem",
                fontFamily: "'Inter', sans-serif",
                textAlign: "left",
              }}
            >
              <span style={{ fontSize: "1rem" }}>⬡</span>
              <span style={{ flex: 1 }}>Tor Monitor</span>
              {torEnabled && (
                <span
                  style={{
                    width: 6,
                    height: 6,
                    background: "#00ff8c",
                    borderRadius: "50%",
                    boxShadow: "0 0 8px #00ff8c",
                  }}
                />
              )}
            </button>
          </div>
        )}
      </div>

      {/* User section */}
      <div
        style={{
          padding: collapsed ? "12px" : "12px 16px",
          borderTop: "1px solid #1a2332",
          display: "flex",
          alignItems: "center",
          gap: 10,
        }}
      >
        <div
          style={{
            width: 32,
            height: 32,
            background: "#1a2332",
            borderRadius: "50%",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
          }}
        >
          <Icon name="user" size={16} color="#64748b" />
        </div>
        {!collapsed && (
          <div style={{ flex: 1 }}>
            <div
              style={{
                fontSize: "0.75rem",
                color: "#e2e8f0",
                fontWeight: 500,
              }}
            >
              SOC Analyst
            </div>
            <div
              style={{
                fontSize: "0.65rem",
                color: "#475569",
                display: "flex",
                alignItems: "center",
                gap: 4,
              }}
            >
              <span
                style={{
                  width: 6,
                  height: 6,
                  background: "#22c55e",
                  borderRadius: "50%",
                }}
              />
              ONLINE
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
