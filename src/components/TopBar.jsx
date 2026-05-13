import React, { useState, useEffect } from "react";

export default function TopBar({ backendStatus, stats }) {
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const interval = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(interval);
  }, []);

  const formatTime = (d) => {
    return d.toLocaleTimeString("en-US", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: true,
    });
  };

  return (
    <div
      style={{
        height: 52,
        background: "#060a12",
        borderBottom: "1px solid #1a2332",
        display: "flex",
        alignItems: "center",
        padding: "0 20px",
        gap: 24,
        flexShrink: 0,
      }}
    >
      {/* View Tabs */}
      <div style={{ display: "flex", gap: 8 }}>
        <button
          style={{
            background: "#0ea5e915",
            border: "1px solid #0ea5e940",
            borderRadius: 6,
            color: "#0ea5e9",
            padding: "6px 14px",
            fontSize: "0.7rem",
            fontFamily: "'Oxanium', sans-serif",
            fontWeight: 600,
            cursor: "pointer",
            letterSpacing: 0.5,
          }}
        >
          GLOBAL VIEW
        </button>
        <button
          style={{
            background: "transparent",
            border: "1px solid #1a2332",
            borderRadius: 6,
            color: "#475569",
            padding: "6px 14px",
            fontSize: "0.7rem",
            fontFamily: "'Oxanium', sans-serif",
            fontWeight: 600,
            cursor: "pointer",
            letterSpacing: 0.5,
            display: "flex",
            alignItems: "center",
            gap: 6,
          }}
        >
          <span
            style={{
              width: 6,
              height: 6,
              background: "#22c55e",
              borderRadius: "50%",
              boxShadow: "0 0 6px #22c55e",
            }}
          />
          LIVE INTELLIGENCE
        </button>
      </div>

      {/* Search */}
      <div style={{ flex: 1, maxWidth: 400 }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            background: "#0a1525",
            border: "1px solid #1a2332",
            borderRadius: 8,
            padding: "0 12px",
            gap: 8,
          }}
        >
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="#475569"
            strokeWidth="2"
          >
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <input
            placeholder="Search places, addresses, IPs, domains..."
            style={{
              background: "transparent",
              border: "none",
              color: "#94a3b8",
              padding: "8px 0",
              fontSize: "0.72rem",
              fontFamily: "'Inter', sans-serif",
              outline: "none",
              width: "100%",
            }}
          />
          <span
            style={{
              color: "#475569",
              fontSize: "0.6rem",
              fontFamily: "monospace",
              background: "#1a2332",
              padding: "2px 6px",
              borderRadius: 4,
            }}
          >
            CTRL K
          </span>
        </div>
      </div>

      {/* AI Assistant Button */}
      <button
        style={{
          background: "linear-gradient(135deg, #8b5cf6, #6366f1)",
          border: "none",
          borderRadius: 8,
          color: "#fff",
          padding: "8px 16px",
          fontSize: "0.72rem",
          fontFamily: "'Inter', sans-serif",
          fontWeight: 600,
          cursor: "pointer",
          display: "flex",
          alignItems: "center",
          gap: 8,
        }}
      >
        <svg
          width="14"
          height="14"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
        >
          <circle cx="12" cy="12" r="3" />
          <path d="M12 1v6M12 17v6M4.22 4.22l4.24 4.24M15.54 15.54l4.24 4.24M1 12h6M17 12h6M4.22 19.78l4.24-4.24M15.54 8.46l4.24-4.24" />
        </svg>
        AI Assistant
      </button>

      {/* Stats */}
      <div style={{ display: "flex", gap: 20 }}>
        {/* Last Update */}
        <div style={{ textAlign: "center" }}>
          <div
            style={{
              fontSize: "0.55rem",
              color: "#475569",
              fontFamily: "monospace",
              letterSpacing: 0.5,
              marginBottom: 2,
            }}
          >
            LAST UPDATE
          </div>
          <div
            style={{
              fontSize: "0.85rem",
              color: "#0ea5e9",
              fontFamily: "'IBM Plex Mono', monospace",
              fontWeight: 600,
            }}
          >
            {formatTime(time)}
          </div>
        </div>

        {/* Alert Level */}
        <div style={{ textAlign: "center" }}>
          <div
            style={{
              fontSize: "0.55rem",
              color: "#475569",
              fontFamily: "monospace",
              letterSpacing: 0.5,
              marginBottom: 2,
            }}
          >
            GLOBAL ALERT LEVEL
          </div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
            }}
          >
            <span
              style={{
                width: 8,
                height: 8,
                background: "#f97316",
                borderRadius: "50%",
                boxShadow: "0 0 8px #f97316",
              }}
            />
            <span
              style={{
                fontSize: "0.8rem",
                color: "#f97316",
                fontFamily: "'Oxanium', sans-serif",
                fontWeight: 700,
                letterSpacing: 1,
              }}
            >
              ELEVATED
            </span>
          </div>
        </div>

        {/* Live Connections */}
        <div style={{ textAlign: "center" }}>
          <div
            style={{
              fontSize: "0.55rem",
              color: "#475569",
              fontFamily: "monospace",
              letterSpacing: 0.5,
              marginBottom: 2,
            }}
          >
            LIVE CONNECTIONS
          </div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
            }}
          >
            <svg
              width="14"
              height="14"
              viewBox="0 0 24 24"
              fill="none"
              stroke="#22c55e"
              strokeWidth="2"
            >
              <circle cx="12" cy="12" r="10" />
              <polyline points="8,12 12,16 16,8" />
            </svg>
            <span
              style={{
                fontSize: "0.9rem",
                color: "#e2e8f0",
                fontFamily: "'IBM Plex Mono', monospace",
                fontWeight: 600,
              }}
            >
              {stats?.liveConnections?.toLocaleString() || "1,964"}
            </span>
          </div>
        </div>

        {/* Threats Detected */}
        <div style={{ textAlign: "center" }}>
          <div
            style={{
              fontSize: "0.55rem",
              color: "#475569",
              fontFamily: "monospace",
              letterSpacing: 0.5,
              marginBottom: 2,
            }}
          >
            THREATS DETECTED (24H)
          </div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
            }}
          >
            <svg
              width="14"
              height="14"
              viewBox="0 0 24 24"
              fill="none"
              stroke="#ef4444"
              strokeWidth="2"
            >
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
              <line x1="12" y1="9" x2="12" y2="13" />
              <line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
            <span
              style={{
                fontSize: "0.9rem",
                color: "#e2e8f0",
                fontFamily: "'IBM Plex Mono', monospace",
                fontWeight: 600,
              }}
            >
              {stats?.threatsDetected || 276}
            </span>
          </div>
        </div>

        {/* Active Assets */}
        <div style={{ textAlign: "center" }}>
          <div
            style={{
              fontSize: "0.55rem",
              color: "#475569",
              fontFamily: "monospace",
              letterSpacing: 0.5,
              marginBottom: 2,
            }}
          >
            ACTIVE ASSETS
          </div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
            }}
          >
            <svg
              width="14"
              height="14"
              viewBox="0 0 24 24"
              fill="none"
              stroke="#0ea5e9"
              strokeWidth="2"
            >
              <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
              <line x1="8" y1="21" x2="16" y2="21" />
              <line x1="12" y1="17" x2="12" y2="21" />
            </svg>
            <span
              style={{
                fontSize: "0.9rem",
                color: "#e2e8f0",
                fontFamily: "'IBM Plex Mono', monospace",
                fontWeight: 600,
              }}
            >
              {stats?.activeAssets?.toLocaleString() || "8,542"}
            </span>
          </div>
        </div>
      </div>

      {/* Right Icons */}
      <div style={{ display: "flex", gap: 8 }}>
        {[
          <svg key="bell" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#64748b" strokeWidth="2">
            <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
            <path d="M13.73 21a2 2 0 0 1-3.46 0" />
          </svg>,
          <svg key="settings" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#64748b" strokeWidth="2">
            <circle cx="12" cy="12" r="3" />
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
          </svg>,
        ].map((icon, i) => (
          <button
            key={i}
            style={{
              width: 36,
              height: 36,
              background: "#0a1525",
              border: "1px solid #1a2332",
              borderRadius: 8,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              cursor: "pointer",
            }}
          >
            {icon}
          </button>
        ))}

        {/* User Avatar */}
        <div
          style={{
            width: 36,
            height: 36,
            background: "linear-gradient(135deg, #0ea5e9, #38bdf8)",
            borderRadius: 8,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: "0.75rem",
            fontWeight: 700,
            color: "#020817",
          }}
        >
          SO
        </div>
      </div>
    </div>
  );
}
