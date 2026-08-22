// ─── API HELPERS ───────────────────────────────────────────────────────────
export async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    ...opts,
  });
  if (!res.ok) throw new Error(`${path} → ${res.status}`);
  return res.json();
}

// SSE → callback for new alerts
export function streamAlerts(onAlert) {
  const es = new EventSource("/api/alerts/stream");
  es.onmessage = (ev) => {
    try {
      const data = JSON.parse(ev.data);
      if (data && data.id) onAlert(data);
    } catch {}
  };
  es.onerror = () => {/* silent reconnect */};
  return () => es.close();
}

// Streaming Claude/agent call (used by Investigations)
export async function callAgent(agentType, messages, onChunk, { system } = {}) {
  const msgs = system ? [{ role: "system", content: system }, ...messages] : messages;
  const res = await fetch("/api/agent", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ agentType, messages: msgs, stream: true }),
  });
  if (!res.ok) {
    const t = `[Agent ${agentType} error: ${res.status}]`;
    onChunk(t); return t;
  }
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let full = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    for (const ln of dec.decode(value).split("\n")) {
      if (!ln.startsWith("data:")) continue;
      const d = ln.slice(5).trim();
      if (d === "[DONE]") continue;
      try {
        const j = JSON.parse(d);
        const t1 = j.choices?.[0]?.delta?.content ?? "";
        const t2 = (j.type === "content_block_delta" && j.delta?.text) ? j.delta.text : "";
        const chunk = t1 || t2;
        if (chunk) { full += chunk; onChunk(full); }
      } catch {}
    }
  }
  return full || `[Agent ${agentType} returned empty response]`;
}

// ─── FORMATTERS ────────────────────────────────────────────────────────────
export function timeAgo(iso) {
  const s = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export const SEV_COLOR = {
  CRITICAL: "sev-critical",
  HIGH:     "sev-high",
  MEDIUM:   "sev-medium",
  LOW:      "sev-low",
};

export const SEV_HEX = {
  CRITICAL: "#ef4444",
  HIGH:     "#f97316",
  MEDIUM:   "#fbbf24",
  LOW:      "#22c55e",
};

// Map common IPs/regions to approximate lat/lng for the threat map
// Falls back to ASN-based hashing for unknown IPs
const COUNTRY_COORDS = {
  US: [38.9, -77.0],   CN: [35.9, 104.2], RU: [55.7, 37.6],   DE: [52.5, 13.4],
  NL: [52.4, 4.9],     SG: [1.35, 103.8], IN: [20.6, 78.9],   BR: [-14.2, -51.9],
  GB: [51.5, -0.1],    UA: [49.0, 32.0],  IR: [32.4, 53.7],   JP: [36.2, 138.3],
  AU: [-25.3, 133.8],  KR: [37.5, 127.0], FR: [46.2, 2.2],    CA: [56.1, -106.3],
  KP: [40.3, 127.5],   SA: [23.9, 45.1],
};

export function geoForCountry(cc) { return COUNTRY_COORDS[cc] || [0, 0]; }

export function ipToApproxGeo(ip = "") {
  const first = parseInt(ip.split(".")[0] || "0", 10);
  if (first >= 1 && first <= 50)   return { lat: 35.9, lng: 104.2, cc: "CN" };
  if (first >= 51 && first <= 79)  return { lat: 38.9, lng: -77.0, cc: "US" };
  if (first >= 80 && first <= 90)  return { lat: 52.5, lng: 13.4, cc: "DE" };
  if (first >= 91 && first <= 100) return { lat: 38.9, lng: -77.0, cc: "US" };
  if (first >= 101 && first <= 130) return { lat: 52.5, lng: 13.4, cc: "DE" };
  if (first >= 131 && first <= 180) return { lat: 55.7, lng: 37.6, cc: "RU" };
  if (first >= 181 && first <= 220) return { lat: 20.6, lng: 78.9, cc: "IN" };
  return { lat: -14.2, lng: -51.9, cc: "BR" };
}
