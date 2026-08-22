import { useContext, useEffect, useMemo, useRef, useState } from "react";
import { CircleMarker, MapContainer, Marker, Polyline, TileLayer, Tooltip, useMap } from "react-leaflet";
import L from "leaflet";
import { OpxdrContext } from "../App";
import { api, timeAgo } from "../lib/api";
import { fetchHoneypotCyberFeed } from "../lib/cyberEvents";
import {
  Activity, Bell, Box, Crosshair, Database, Download, Eye,
  FileText, Globe, Layers, Minus, Network, Plus, RefreshCw, Search, Send,
  Server, Settings, Shield, Sparkles, X, Zap,
} from "../lib/icons";

const SERVICE_LABELS = {
  ssh: "Cowrie SSH",
  http: "HTTP Web Trap",
  ftp: "FTP Drop Trap",
  smb: "SMB Share Lure",
  smtp: "SMTP Relay Trap",
};

const SERVICE_TECHNIQUE = {
  ssh: "T1110 Brute Force",
  http: "T1190 Exploit Public-Facing App",
  ftp: "T1110 Brute Force",
  smb: "T1021.002 SMB Admin Shares",
  smtp: "T1598 Phishing for Information",
};

const SERVICE_COLOR = {
  ssh: "#ff554f",
  http: "#ff7a18",
  ftp: "#fbbf24",
  smb: "#8b5cf6",
  smtp: "#38bdf8",
};

const CC_FLAG = { US:"🇺🇸", CN:"🇨🇳", RU:"🇷🇺", DE:"🇩🇪", NL:"🇳🇱", IR:"🇮🇷", UA:"🇺🇦", GB:"🇬🇧", BR:"🇧🇷", IN:"🇮🇳", JP:"🇯🇵", KP:"🇰🇵", SG:"🇸🇬", AU:"🇦🇺", FR:"🇫🇷", CA:"🇨🇦", EG:"🇪🇬" };
const CC_CITY = { DE:"Frankfurt, DE", RU:"Moscow, RU", IN:"Bengaluru, IN", BR:"Sao Paulo, BR", AU:"Sydney, AU", CA:"Toronto, CA", EG:"Cairo, EG", US:"United States", CN:"China", IR:"Tehran, IR", NL:"Amsterdam, NL" };

function severityClass(sev) {
  if (sev === "critical") return "text-sev-critical border-sev-critical/40 bg-sev-critical/10";
  if (sev === "high") return "text-sev-high border-sev-high/40 bg-sev-high/10";
  if (sev === "medium") return "text-sev-medium border-sev-medium/40 bg-sev-medium/10";
  return "text-info border-info/40 bg-info/10";
}

function latLng(point = {}) {
  const lat = Number(point.lat);
  const lng = Number(point.lng);
  if (!Number.isFinite(lat) || !Number.isFinite(lng)) return null;
  return [lat, lng];
}

function locationKey(location = {}) {
  const ll = latLng(location);
  if (!ll) return "unknown";
  return `${ll[0].toFixed(3)},${ll[1].toFixed(3)}`;
}

function honeypotMarkerIcon({ enabled, status, count, offset = [0, 0] }) {
  const active = enabled && status === "active";
  const color = count > 0 ? "#ff7a18" : active ? "#22c55e" : "#64748b";
  const ring = count > 0 ? "rgba(255,122,24,.42)" : active ? "rgba(34,197,94,.32)" : "rgba(100,116,139,.25)";
  return L.divIcon({
    className: "opxdr-honeypot-marker",
    iconSize: [42, 42],
    iconAnchor: [21 - offset[0], 21 - offset[1]],
    html: `<div style="width:42px;height:42px;border-radius:12px;border:1px solid ${color};background:rgba(9,14,28,.92);box-shadow:0 0 0 6px ${ring},0 0 26px ${ring};display:flex;align-items:center;justify-content:center;position:relative;"><div style="width:20px;height:17px;display:flex;flex-direction:column;gap:3px;"><i style="height:3px;border-radius:4px;background:${color};box-shadow:0 0 10px ${color};"></i><i style="height:3px;border-radius:4px;background:${color};box-shadow:0 0 10px ${color};"></i><i style="height:3px;border-radius:4px;background:${color};box-shadow:0 0 10px ${color};"></i></div><span style="position:absolute;right:-6px;top:-7px;min-width:18px;height:18px;padding:0 4px;border-radius:999px;border:1px solid rgba(255,255,255,.35);background:${color};color:#020617;font-size:10px;line-height:17px;text-align:center;font-family:monospace;font-weight:800;">${count}</span></div>`,
  });
}

function markerOffset(index, total) {
  if (total <= 1) return [0, 0];
  const angle = (Math.PI * 2 * index) / total - Math.PI / 2;
  const radius = Math.min(34, 16 + total * 4);
  return [Math.cos(angle) * radius, Math.sin(angle) * radius];
}

function arcPositions(src, dst) {
  const start = latLng(src);
  const end = latLng(dst);
  if (!start || !end) return [];
  const [lat1, lng1] = start;
  const [lat2, lng2] = end;
  const distance = Math.max(Math.abs(lat2 - lat1), Math.abs(lng2 - lng1));
  const lift = Math.min(32, Math.max(6, distance * 0.16));
  return Array.from({ length: 42 }, (_, i) => {
    const t = i / 41;
    const lat = lat1 + (lat2 - lat1) * t + Math.sin(Math.PI * t) * lift;
    const lng = lng1 + (lng2 - lng1) * t;
    return [lat, lng];
  });
}

function FitMap({ events, honeypots }) {
  const map = useMap();
  const key = useMemo(() => [
    ...honeypots.flatMap(h => [h.location?.lat, h.location?.lng]),
    ...events.slice(0, 8).flatMap(e => [e.src?.lat, e.src?.lng, e.dst?.lat, e.dst?.lng]),
  ].join("|"), [events, honeypots]);

  useEffect(() => {
    const points = [
      ...honeypots.map(h => latLng(h.location)),
      ...events.slice(0, 8).flatMap(e => [latLng(e.src), latLng(e.dst)]),
    ].filter(Boolean);
    if (points.length > 1) {
      map.fitBounds(points, { padding: [70, 70], maxZoom: 5, animate: true });
      return;
    }
    if (points.length === 1) map.setView(points[0], 4, { animate: true });
  }, [map, key]);

  return null;
}

function ZoomControls({ destination }) {
  const map = useMap();
  return (
    <div className="absolute left-4 bottom-4 z-[500] flex flex-col gap-1 rounded-lg border border-border bg-bg-1/85 p-1 shadow-xl backdrop-blur">
      <button title="Zoom in" onClick={() => map.zoomIn()} className="w-9 h-9 rounded-md border border-border bg-bg-2 text-ink-1 hover:text-ink-0 hover:bg-bg-3 flex items-center justify-center"><Plus size={15} /></button>
      <button title="Zoom out" onClick={() => map.zoomOut()} className="w-9 h-9 rounded-md border border-border bg-bg-2 text-ink-1 hover:text-ink-0 hover:bg-bg-3 flex items-center justify-center"><Minus size={15} /></button>
      <button title="Center honeypot" onClick={() => latLng(destination) && map.setView(latLng(destination), 5)} className="w-9 h-9 rounded-md border border-border bg-bg-2 text-brand-accent hover:bg-bg-3 flex items-center justify-center"><Crosshair size={15} /></button>
    </div>
  );
}

export default function GlobalMap() {
  const { alerts } = useContext(OpxdrContext);
  const [agents, setAgents] = useState([]);
  const [agentsLoading, setAgentsLoading] = useState(true);
  const [enabledAgents, setEnabledAgents] = useState({});
  const [agentBusy, setAgentBusy] = useState({});
  const [events, setEvents] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [serviceFilter, setServiceFilter] = useState("ALL");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [windowFilter, setWindowFilter] = useState("LIVE");
  const latestEventTsRef = useRef(null);

  const activeAgentIds = useMemo(() => Object.entries(enabledAgents).filter(([, on]) => on).map(([id]) => id), [enabledAgents]);
  const activeAgentKey = activeAgentIds.join(",");
  const monitoringOn = activeAgentIds.length > 0;

  useEffect(() => {
    let cancelled = false;
    setAgentsLoading(true);
    api("/api/agents")
      .then(j => {
        if (cancelled) return;
        const list = Array.isArray(j.agents) && j.agents.length
          ? j.agents
          : [{ id: "local", name: "soc-admin", ip: "100.86.115.94", status: "active", os: { name: "Ubuntu" }, group: "opxdr" }];
        setAgents(list);
        setEnabledAgents(prev => Object.keys(prev).length ? prev : Object.fromEntries(list.map(a => [String(a.id), !!a.honeypotStatus?.running])));
      })
      .catch(() => {
        if (cancelled) return;
        const fallback = [{ id: "local", name: "soc-admin", ip: "100.86.115.94", status: "active", os: { name: "Ubuntu" }, group: "opxdr" }];
        setAgents(fallback);
        setEnabledAgents(prev => Object.keys(prev).length ? prev : { local: false });
      })
      .finally(() => { if (!cancelled) setAgentsLoading(false); });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    latestEventTsRef.current = events[0]?.timestamp || null;
    if (!selectedId && events[0]) setSelectedId(events[0].id);
  }, [events, selectedId]);

  useEffect(() => {
    if (!monitoringOn) {
      setEvents([]);
      setSelectedId(null);
      return;
    }
    fetchHoneypotCyberFeed({ limit: 100, agentIds: activeAgentIds }).then(next => {
      setEvents(next);
      setSelectedId(prev => prev || next[0]?.id || null);
    });
  }, [monitoringOn, activeAgentKey]);

  useEffect(() => {
    if (!monitoringOn) return;
    const timer = setInterval(async () => {
      const since = latestEventTsRef.current || new Date(Date.now() - 60_000).toISOString();
      const incoming = await fetchHoneypotCyberFeed({ limit: 25, since, agentIds: activeAgentIds });
      setEvents(prev => {
        const seen = new Set();
        return [...incoming, ...prev].filter(e => {
          if (seen.has(e.id)) return false;
          seen.add(e.id);
          return true;
        }).slice(0, 250);
      });
    }, 5000);
    return () => clearInterval(timer);
  }, [monitoringOn, activeAgentKey]);

  async function refreshAgents() {
    const j = await api("/api/agents");
    const list = Array.isArray(j.agents) && j.agents.length ? j.agents : [];
    setAgents(list);
    setEnabledAgents(Object.fromEntries(list.map(a => [String(a.id), !!a.honeypotStatus?.running])));
    return list;
  }

  async function toggleAgent(id) {
    const key = String(id);
    const nextEnabled = !enabledAgents[key];
    setAgentBusy(prev => ({ ...prev, [key]: true }));
    try {
      const result = await api(`/api/honeypot/agents/${encodeURIComponent(key)}/state`, {
        method: "POST",
        body: JSON.stringify({ enabled: nextEnabled }),
      });
      setEnabledAgents(prev => ({ ...prev, [key]: !!result.status?.running }));
      await refreshAgents();
    } catch (e) {
      console.warn("honeypot control failed", e);
      await refreshAgents().catch(() => {});
    } finally {
      setAgentBusy(prev => ({ ...prev, [key]: false }));
    }
  }

  const filteredEvents = useMemo(() => {
    return events.filter(e => {
      const service = e.service || e.dst?.service || "unknown";
      if (serviceFilter !== "ALL" && service !== serviceFilter) return false;
      if (severityFilter !== "ALL" && e.severity !== severityFilter.toLowerCase()) return false;
      return true;
    });
  }, [events, serviceFilter, severityFilter]);

  const selectedEvent = filteredEvents.find(e => e.id === selectedId) || filteredEvents[0] || null;
  const mapEvents = filteredEvents.slice(0, 18).filter(e => latLng(e.src) && latLng(e.dst));
  const dst = selectedEvent?.dst || events[0]?.dst || { lat: 40.7128, lng: -74.006, name: "New York, USA", host: "soc-admin", cc: "US", port: 2222, systemLocation: "default" };
  const agentStats = useMemo(() => {
    const stats = new Map();
    for (const event of filteredEvents) {
      const id = String(event.agentId || event.dst?.agentId || event.dst?.host || "local");
      const prev = stats.get(id) || { count: 0, critical: 0, high: 0, services: new Set(), lastSeen: null, location: event.dst };
      prev.count += 1;
      if (event.severity === "critical") prev.critical += 1;
      if (event.severity === "high") prev.high += 1;
      if (event.service) prev.services.add(event.service);
      if (!prev.lastSeen || new Date(event.timestamp) > new Date(prev.lastSeen)) prev.lastSeen = event.timestamp;
      if (event.dst) prev.location = event.dst;
      stats.set(id, prev);
    }
    return stats;
  }, [filteredEvents]);
  const honeypotMarkers = useMemo(() => {
    const markers = agents.map(agent => {
      const id = String(agent.id);
      const stats = agentStats.get(id) || { count: 0, critical: 0, high: 0, services: new Set(), lastSeen: null };
      const trafficLocation = filteredEvents.find(e => String(e.agentId) === id && e.dst)?.dst;
      return {
        id,
        agent,
        enabled: !!enabledAgents[id],
        location: trafficLocation || agent.honeypotLocation || dst,
        stats,
      };
    }).filter(m => latLng(m.location));
    const groups = markers.reduce((acc, marker) => {
      const key = locationKey(marker.location);
      acc.set(key, [...(acc.get(key) || []), marker.id]);
      return acc;
    }, new Map());
    return markers.map(marker => {
      const group = groups.get(locationKey(marker.location)) || [marker.id];
      const index = group.indexOf(marker.id);
      return { ...marker, offset: markerOffset(index, group.length), overlapCount: group.length };
    });
  }, [agents, agentStats, dst, enabledAgents, filteredEvents]);
  const critical = filteredEvents.filter(e => e.severity === "critical").length;
  const countries = new Set(filteredEvents.map(e => e.src?.cc).filter(Boolean)).size;
  const rate = Math.max(0, Math.min(99, (filteredEvents.length / 10).toFixed(1)));

  function exportCSV() {
    const header = "time,source,ip,honeypot,agent,technique,destination,severity";
    const body = filteredEvents.map(e => [
      new Date(e.timestamp).toLocaleTimeString(),
      CC_CITY[e.src?.cc] || e.src?.name || e.src?.cc || "Unknown",
      e.src?.ip || "-",
      SERVICE_LABELS[e.service] || e.service || "Honeypot",
      e.dst?.host || e.agentId || "-",
      SERVICE_TECHNIQUE[e.service] || e.mitre || "-",
      `${e.dst?.port || "-"} / TCP`,
      e.severity,
    ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(",")).join("\n");
    const blob = new Blob([[header, body].join("\n")], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `opxdr_honeypot_${new Date().toISOString().slice(0, 19).replace(/:/g, "-")}.csv`;
    a.click();
  }

  return (
    <div className="p-5 space-y-4">
      <div className="grid grid-cols-4 gap-3">
        <Metric icon={Activity} value={filteredEvents.length.toLocaleString()} label="Events" sub="Live" tone="brand" />
        <Metric icon={Globe} value={countries} label="Countries" sub="Sources" tone="info" />
        <Metric icon={Shield} value={critical} label="Critical" sub="High severity" tone="critical" />
        <Metric icon={Zap} value={rate} label="Attacks/min" sub="Live rate" tone="info" spark />
      </div>

      <div className="grid grid-cols-[1fr_300px] gap-3">
        <div className="panel overflow-hidden bg-[#060b17] border-[#253150]">
          <div className="flex items-center gap-2 px-3 py-2 border-b border-border/60 bg-bg-1/80">
            <button onClick={() => setWindowFilter("LIVE")} className={`px-3 py-1 rounded-md text-2xs font-bold ${windowFilter === "LIVE" ? "bg-brand text-white" : "bg-bg-2 text-ink-2"}`}>LIVE</button>
            {["1H", "24H", "7D"].map(w => <button key={w} onClick={() => setWindowFilter(w)} className="px-3 py-1 rounded-md text-2xs font-mono bg-bg-2 text-ink-2 hover:text-ink-0">{w}</button>)}
            <select value={serviceFilter} onChange={e => setServiceFilter(e.target.value)} className="ml-2 bg-bg-2 border border-border rounded-md px-3 py-1.5 text-2xs text-ink-1 outline-none">
              <option value="ALL">ALL PROTOCOLS</option>
              <option value="ssh">SSH</option>
              <option value="http">HTTP</option>
              <option value="ftp">FTP</option>
              <option value="smb">SMB</option>
              <option value="smtp">SMTP</option>
            </select>
            <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)} className="bg-bg-2 border border-border rounded-md px-3 py-1.5 text-2xs text-ink-1 outline-none">
              <option value="ALL">SEVERITY</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
            <div className="ml-auto flex items-center gap-2 text-3xs text-ink-3 font-mono">
              {agentsLoading ? "Loading agents" : `${activeAgentIds.length}/${agents.length} honeypots monitored`}
            </div>
          </div>

          <div className="px-3 py-2 flex gap-2 overflow-x-auto border-b border-border/50 bg-bg-0/40">
            {agents.map(agent => {
              const id = String(agent.id);
              const on = !!enabledAgents[id];
              const busy = !!agentBusy[id];
              const installed = !!agent.honeypotStatus?.installed;
              return (
                <button key={id} disabled={busy || !installed} onClick={() => toggleAgent(id)} className={`min-w-[190px] rounded-md border px-3 py-2 text-left ${on ? "border-brand/50 bg-brand/10" : "border-border bg-bg-2/60"} ${busy ? "opacity-70" : ""} ${!installed ? "cursor-not-allowed" : ""}`}>
                  <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full ${on ? "bg-ok" : "bg-ink-3"}`} />
                    <span className="text-xs font-bold text-ink-0 truncate">{agent.name || `Agent ${id}`}</span>
                    <span className={`ml-auto relative w-8 h-5 rounded-full border ${on ? "bg-brand border-brand" : "bg-bg-3 border-border"}`}>
                      <span className={`absolute top-0.5 w-3.5 h-3.5 rounded-full bg-white transition-all ${on ? "left-[17px]" : "left-0.5"}`} />
                    </span>
                  </div>
                  <div className="mt-1 text-3xs font-mono text-ink-3 truncate">{agent.ip || "no ip"} · {busy ? "switching" : agent.honeypotStatus?.running ? "honeypot running" : agent.honeypotStatus?.installed ? "honeypot off" : "not installed"}</div>
                </button>
              );
            })}
          </div>

          <div className="relative h-[560px] overflow-hidden bg-[#020611]">
            <MapContainer
              center={latLng(dst) || [28, 10]}
              zoom={latLng(dst) ? 3 : 2}
              minZoom={2}
              maxZoom={10}
              zoomControl={false}
              scrollWheelZoom
              worldCopyJump
              className="absolute inset-0 z-0 h-full w-full"
              style={{ background: "#020611" }}
            >
              <TileLayer
                url="https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}"
                attribution="Tiles &copy; Esri"
              />
              <TileLayer
                url="https://{s}.basemaps.cartocdn.com/dark_only_labels/{z}/{x}/{y}{r}.png"
                attribution="&copy; CARTO &copy; OpenStreetMap"
                subdomains="abcd"
                opacity={0.88}
              />
              <FitMap events={mapEvents} honeypots={honeypotMarkers} />

              {mapEvents.map((event, idx) => {
                const color = SERVICE_COLOR[event.service] || "#ff554f";
                return (
                  <Polyline
                    key={`arc-${event.id}`}
                    positions={arcPositions(event.src, event.dst || dst)}
                    pathOptions={{ color, weight: selectedEvent?.id === event.id ? 3 : 1.8, opacity: selectedEvent?.id === event.id ? 0.95 : 0.65, dashArray: idx % 2 ? "6,8" : undefined }}
                    eventHandlers={{ click: () => setSelectedId(event.id) }}
                  />
                );
              })}

              {mapEvents.map(event => {
                const color = SERVICE_COLOR[event.service] || "#ff554f";
                const selected = selectedEvent?.id === event.id;
                return (
                  <CircleMarker
                    key={`src-${event.id}`}
                    center={latLng(event.src)}
                    radius={selected ? 8 : 5}
                    pathOptions={{ color: selected ? "#ffffff" : color, weight: selected ? 3 : 1.5, fillColor: color, fillOpacity: 0.95 }}
                    eventHandlers={{ click: () => setSelectedId(event.id) }}
                  >
                    <Tooltip direction="top" offset={[0, -8]} opacity={1} permanent={selected} className="!bg-bg-1/95 !border !border-border !text-ink-0 !shadow-xl">
                      <div className="font-mono text-2xs">
                        <div>{CC_FLAG[event.src?.cc] || ""} {CC_CITY[event.src?.cc] || event.src?.name || event.src?.cc || "Unknown"}</div>
                        <div>{event.src?.ip || "-"}</div>
                      </div>
                    </Tooltip>
                  </CircleMarker>
                );
              })}

              {honeypotMarkers.map(marker => {
                const selectedAgent = selectedEvent && String(selectedEvent.agentId) === marker.id;
                const services = marker.stats.services?.size ? [...marker.stats.services].map(s => SERVICE_LABELS[s] || s).join(", ") : "No traffic yet";
                return (
                  <Marker
                    key={`honeypot-${marker.id}`}
                    position={latLng(marker.location)}
                    icon={honeypotMarkerIcon({ enabled: marker.enabled, status: marker.agent.status, count: marker.stats.count, offset: marker.offset })}
                    eventHandlers={{ click: () => {
                      const event = filteredEvents.find(e => String(e.agentId) === marker.id);
                      if (event) setSelectedId(event.id);
                    } }}
                  >
                    <Tooltip direction="right" offset={[16, 0]} opacity={1} permanent={selectedAgent} className="!bg-bg-1/95 !border !border-brand/50 !text-ink-0 !shadow-xl">
                      <div className="min-w-52">
                        <div className="text-xs font-extrabold">OPXDR HONEYPOT</div>
                        <div className="text-2xs text-brand-accent">{marker.agent.name || marker.location.host || `Agent ${marker.id}`}</div>
                        <div className="grid grid-cols-[72px_1fr] gap-x-2 gap-y-1 mt-2 text-3xs font-mono">
                          <span className="text-ink-3">Agent</span><span>{marker.id}</span>
                          <span className="text-ink-3">IP</span><span>{marker.agent.ip || marker.location.ip || "-"}</span>
                          <span className="text-ink-3">OS</span><span>{marker.agent.os?.name || "Unknown"}</span>
                          <span className="text-ink-3">Status</span><span className={marker.agent.honeypotStatus?.running ? "text-ok" : "text-ink-2"}>{marker.agent.honeypotStatus?.running ? "honeypot running" : "honeypot off"}</span>
                          <span className="text-ink-3">Traffic</span><span>{marker.stats.count} events · {marker.stats.critical} critical</span>
                          <span className="text-ink-3">Ports</span><span>{marker.agent.honeypotStatus?.services?.filter(s => s.listening).map(s => s.port).join(", ") || "not listening"}</span>
                          <span className="text-ink-3">Services</span><span>{services}</span>
                          <span className="text-ink-3">Location</span><span>{marker.location.name || marker.location.cc || "Unknown"}</span>
                          <span className="text-ink-3">Coords</span><span>{Number(marker.location.lat).toFixed(4)}, {Number(marker.location.lng).toFixed(4)}</span>
                          <span className="text-ink-3">Last</span><span>{marker.stats.lastSeen ? timeAgo(marker.stats.lastSeen) : "waiting"}</span>
                        </div>
                      </div>
                    </Tooltip>
                  </Marker>
                );
              })}

              <ZoomControls destination={dst} />
            </MapContainer>

            <div className="pointer-events-none absolute inset-0 z-[410] shadow-[inset_0_0_90px_rgba(2,6,17,.8)]" />
            <div className="absolute left-4 top-24 z-[500] flex flex-col gap-3 rounded-xl border border-border bg-bg-1/80 p-3 backdrop-blur">
              <ToolIcon icon={Crosshair} label="Attacks" active />
              <ToolIcon icon={Server} label="Honeypots" />
              <ToolIcon icon={Globe} label="Countries" />
              <ToolIcon icon={Layers} label="Heatmap" />
              <ToolIcon icon={Box} label="Grid" />
            </div>
          </div>
        </div>

        <LiveAttackPanel event={selectedEvent} onInvestigate={() => selectedEvent && setSelectedId(selectedEvent.id)} />
      </div>

      <ThreatLogTable events={filteredEvents} selectedId={selectedId} onSelect={setSelectedId} onExport={exportCSV} />
    </div>
  );
}

function Metric({ icon: Icon, value, label, sub, tone, spark }) {
  const colors = tone === "critical" ? "text-sev-critical bg-sev-critical/10" : tone === "info" ? "text-info bg-info/10" : "text-brand-accent bg-brand/10";
  return (
    <div className="panel p-4 flex items-center gap-4 min-h-24">
      <div className={`w-14 h-14 rounded-xl flex items-center justify-center ${colors}`}><Icon size={24} /></div>
      <div className="min-w-0">
        <div className="text-2xl font-extrabold text-ink-0 tracking-tight">{value}</div>
        <div className="text-2xs uppercase tracking-widest text-ink-2 font-bold">{label}</div>
        <div className="text-2xs text-ink-3">{sub}</div>
      </div>
      {spark && <div className="ml-auto w-24 h-8"><Sparkline /></div>}
    </div>
  );
}

function ToolIcon({ icon: Icon, label, active }) {
  return <button title={label} className={`w-11 h-11 rounded-lg border flex items-center justify-center ${active ? "bg-brand/30 border-brand text-brand-accent" : "bg-bg-2 border-border text-ink-2"}`}><Icon size={18} /></button>;
}

function LiveAttackPanel({ event, onInvestigate }) {
  if (!event) {
    return (
      <div className="panel p-4 bg-bg-1/90 min-h-[640px]">
        <div className="flex items-center justify-between mb-6"><div className="panel-title">Live Attack</div><X size={14} className="text-ink-3" /></div>
        <div className="text-2xs text-ink-3 py-10 text-center">No honeypot traffic selected</div>
      </div>
    );
  }
  const service = event.service || event.dst?.service;
  return (
    <div className="panel p-4 bg-bg-1/90 min-h-[640px]">
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-2"><span className="w-2 h-2 rounded-full bg-sev-critical" /><div className="text-sm font-extrabold uppercase tracking-wider text-ink-0">Live Attack</div></div>
        <X size={14} className="text-ink-3" />
      </div>
      <div className={`inline-flex px-3 py-1.5 rounded-md border text-2xs font-bold uppercase mb-4 ${severityClass(event.severity)}`}>{event.severity} severity</div>
      <DetailRow icon={Network} k="Source IP" v={event.src?.ip} />
      <DetailRow icon={Globe} k="Origin" v={`${CC_FLAG[event.src?.cc] || ""} ${CC_CITY[event.src?.cc] || event.src?.name || event.src?.cc}`} />
      <DetailRow icon={Server} k="Target" v={event.dst?.host || "soc-admin"} />
      <DetailRow icon={Layers} k="Honeypot" v={SERVICE_LABELS[service] || service || "Honeypot"} />
      <DetailRow icon={Database} k="Port / Protocol" v={`${event.dst?.port || "-"} / TCP`} />
      <DetailRow icon={Activity} k="ASN" v={event.asn || "AS60729"} />
      <DetailRow icon={Shield} k="Technique" v={SERVICE_TECHNIQUE[service] || event.mitre || "-"} />
      <DetailRow icon={RefreshCw} k="First Seen" v={new Date(event.timestamp).toLocaleString()} />
      <DetailRow icon={Eye} k="Last Seen" v={timeAgo(event.timestamp)} />
      <DetailRow icon={FileText} k="Events" v="1" />
      <button onClick={onInvestigate} className="btn btn-accent w-full mt-6 justify-between">Investigate <Send size={15} /></button>
      <button className="btn btn-outline w-full mt-3 text-sev-critical border-sev-critical/40">Block IP <X size={14} /></button>
    </div>
  );
}

function DetailRow({ icon: Icon, k, v }) {
  return (
    <div className="grid grid-cols-[24px_82px_1fr] gap-2 items-center py-3 border-b border-border/50 text-2xs">
      <Icon size={14} className="text-ink-3" />
      <span className="text-ink-3">{k}</span>
      <span className="text-ink-0 font-medium text-right truncate">{v || "-"}</span>
    </div>
  );
}

function ThreatLogTable({ events, selectedId, onSelect, onExport }) {
  return (
    <div className="panel overflow-hidden">
      <div className="flex items-center gap-3 px-4 py-3 border-b border-border bg-bg-1/80">
        <div className="text-sm font-extrabold uppercase tracking-wider text-brand-accent">Cyber Threat Log</div>
        <span className="live-dot" />
        <span className="text-2xs text-ink-3">Live events</span>
        <div className="ml-auto flex items-center gap-3 text-2xs text-ink-3"><span>Auto-refresh</span><span>5s</span><button onClick={onExport} className="btn btn-ghost text-2xs"><Download size={12} /> Export</button></div>
      </div>
      <div className="grid grid-cols-[120px_1.1fr_1.2fr_1.4fr_1fr_90px] px-4 py-2 border-b border-border text-3xs uppercase tracking-widest text-ink-3 font-bold">
        <div>Time</div><div>Source</div><div>Honeypot</div><div>Technique</div><div>Destination</div><div>Severity</div>
      </div>
      <div className="max-h-56 overflow-y-auto">
        {events.length === 0 ? <div className="text-center text-2xs text-ink-3 py-10">No monitored honeypot traffic yet</div> : events.map(event => {
          const service = event.service || event.dst?.service;
          const color = SERVICE_COLOR[service] || "#8b5cf6";
          return (
            <button key={event.id} onClick={() => onSelect(event.id)} className={`grid grid-cols-[120px_1.1fr_1.2fr_1.4fr_1fr_90px] w-full px-4 py-2.5 border-b border-border/50 text-left text-2xs hover:bg-bg-2 ${selectedId === event.id ? "bg-brand/10" : ""}`}>
              <div className="font-mono text-ink-2"><span className="inline-block w-2 h-2 rounded-full mr-3" style={{ background: color }} />{new Date(event.timestamp).toLocaleTimeString()}</div>
              <div className="text-ink-0"><span className="mr-2">{CC_FLAG[event.src?.cc] || ""}</span>{CC_CITY[event.src?.cc] || event.src?.name || event.src?.cc}<span className="text-ink-3 font-mono ml-3">{event.src?.ip}</span></div>
              <div className="text-ink-0">{SERVICE_LABELS[service] || service || "Honeypot"}<span className="text-ink-3 font-mono ml-3">{event.dst?.host || event.agentId}</span></div>
              <div className="text-ink-1">{SERVICE_TECHNIQUE[service] || event.mitre || "-"}</div>
              <div className="text-ink-1 font-mono">{event.dst?.port || "-"} / TCP</div>
              <div><span className={`px-2 py-1 rounded border text-3xs font-bold uppercase ${severityClass(event.severity)}`}>{event.severity}</span></div>
            </button>
          );
        })}
      </div>
    </div>
  );
}

function Sparkline() {
  return <svg viewBox="0 0 100 34" className="w-full h-full"><polyline points="0,28 12,25 24,26 36,20 48,24 60,16 72,19 84,10 94,18 100,5" fill="none" stroke="#8b5cf6" strokeWidth="3" /></svg>;
}
