import { createContext, useCallback, useEffect, useRef, useState } from "react";
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from "react-router-dom";
import AppLayout from "./layout/AppLayout";
import Overview from "./pages/Overview";
import GlobalMap from "./pages/GlobalMap";
import Registry from "./pages/Registry";
import ActiveAlerts from "./pages/ActiveAlerts";
import Investigations from "./pages/Investigations";
import Documents from "./pages/Documents";
import TorMonitorPage from "./pages/TorMonitorPage";
import Settings from "./pages/Settings";
import AssetInventory from "./pages/AssetInventory";
import ThreatFeeds from "./pages/ThreatFeeds";
import {
  Indicators, AttackPatterns,
  NetworkMap, Vulnerabilities,
  Playbooks, Responses, Integrations,
} from "./pages/Placeholders";
import { streamAlerts, api } from "./lib/api";

export const OpxdrContext = createContext({
  alerts: [], setAlerts: () => {},
  backendStatus: null,
  savedDocs: [], setSavedDocs: () => {},
  customRules: [], setCustomRules: () => {},
});

const SK_RULES = "wazuh_soc_rules_v4";
const SK_DOCS = "opxdr_documents_v1";

function loadLS(key) {
  try { const r = localStorage.getItem(key); return r ? JSON.parse(r) : null; } catch { return null; }
}
function saveLS(key, v) {
  try { localStorage.setItem(key, JSON.stringify(v)); } catch {}
}

function normalizeAlert(a) {
  return {
    ...a,
    iocs: Array.isArray(a.iocs) ? a.iocs : [],
    irId: a.irId || null,
  };
}

function NavBridge({ children }) {
  const navigate = useNavigate();
  useEffect(() => {
    const handler = (e) => {
      const target = e.detail;
      if (target === "registry") navigate("/registry");
      else if (target) navigate("/" + target);
    };
    window.addEventListener("opxdr-nav", handler);
    return () => window.removeEventListener("opxdr-nav", handler);
  }, [navigate]);
  return children;
}

export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [refreshingAlerts, setRefreshingAlerts] = useState(false);
  const [backendStatus, setBackendStatus] = useState(null);
  const [savedDocs, setSavedDocs] = useState([]);
  const [customRules, setCustomRules] = useState([]);
  const autoSeenRef = useRef(new Set());
  const docsSaveTimer = useRef(null);

  // Load from backend on startup, fall back to localStorage
  useEffect(() => {
    api("/api/documents")
      .then(j => { if (Array.isArray(j.documents) && j.documents.length) setSavedDocs(j.documents); })
      .catch(() => {
        const docs = loadLS(SK_DOCS);
        if (docs) setSavedDocs(docs);
      });
    const rules = loadLS(SK_RULES);
    if (rules) setCustomRules(rules);
  }, []);

  // Sync savedDocs to backend + localStorage (debounced)
  useEffect(() => {
    saveLS(SK_DOCS, savedDocs);
    if (docsSaveTimer.current) clearTimeout(docsSaveTimer.current);
    docsSaveTimer.current = setTimeout(() => {
      api("/api/documents", {
        method: "POST",
        body: JSON.stringify({ documents: savedDocs }),
      }).catch(() => {});
    }, 2000);
  }, [savedDocs]);
  useEffect(() => { saveLS(SK_RULES, customRules); }, [customRules]);

  useEffect(() => {
    api("/api/health")
      .then(() => setBackendStatus("ok"))
      .catch(() => setBackendStatus("down"));
  }, []);

  useEffect(() => {
    api("/api/alerts/persisted?limit=500")
      .then(j => {
        if (Array.isArray(j.alerts) && j.alerts.length) {
          setAlerts(j.alerts.map(normalizeAlert));
        }
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    const stop = streamAlerts((a) => {
      if (!a || !a.id) return;
      if (a.severity === "LOW") return;
      if (autoSeenRef.current.has(a.id)) return;
      autoSeenRef.current.add(a.id);
      const norm = normalizeAlert(a);
      setAlerts(prev => {
        if (prev.some(x => x.id === norm.id)) return prev;
        const next = [norm, ...prev];
        return next.length > 500 ? next.slice(0, 500) : next;
      });
    });
    return stop;
  }, []);

  async function refreshAlerts() {
    setRefreshingAlerts(true);
    try {
      const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
      const j = await api(`/api/alerts/recent?since=${encodeURIComponent(since)}&limit=500&min_level=7`);
      if (Array.isArray(j.alerts)) {
        setAlerts(j.alerts.map(normalizeAlert));
      }
    } catch (e) {
      console.warn("refreshAlerts failed:", e.message);
    } finally {
      setRefreshingAlerts(false);
    }
  }

  const ctx = {
    alerts, setAlerts,
    refreshAlerts, refreshingAlerts,
    backendStatus,
    savedDocs, setSavedDocs,
    customRules, setCustomRules,
  };

  return (
    <OpxdrContext.Provider value={ctx}>
      <BrowserRouter>
        <NavBridge>
          <Routes>
            <Route element={<AppLayout />}>
              <Route path="/" element={<Overview />} />
              <Route path="/map" element={<GlobalMap />} />
              <Route path="/registry" element={<Registry />} />
              <Route path="/alerts" element={<ActiveAlerts />} />
              <Route path="/investigations" element={<Investigations />} />
              <Route path="/geo" element={<Navigate to="/map" replace />} />
              <Route path="/tor" element={<TorMonitorPage />} />
              <Route path="/feeds" element={<ThreatFeeds />} />
              <Route path="/iocs" element={<Indicators />} />
              <Route path="/patterns" element={<AttackPatterns />} />
              <Route path="/assets" element={<AssetInventory />} />
              <Route path="/network" element={<NetworkMap />} />
              <Route path="/vulns" element={<Vulnerabilities />} />
              <Route path="/playbooks" element={<Playbooks />} />
              <Route path="/responses" element={<Responses />} />
              <Route path="/integrations" element={<Integrations />} />
              <Route path="/reports" element={<Documents />} />
              <Route path="/documents" element={<Documents />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Route>
          </Routes>
        </NavBridge>
      </BrowserRouter>
    </OpxdrContext.Provider>
  );
}
