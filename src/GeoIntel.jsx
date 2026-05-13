import { useCallback, useEffect, useRef } from "react";

export default function GeoIntel() {
  const iframeRef = useRef(null);
  const goBack = useCallback(() => {
    window.dispatchEvent(new CustomEvent("opxdr-nav", { detail: "registry" }));
  }, []);

  useEffect(() => {
    const el = iframeRef.current;
    if (!el) return;
    const onLoad = () => {
      try {
        const gmapsKey = import.meta.env.VITE_GMAPS_KEY;
        if (gmapsKey) {
          el.contentWindow.postMessage({ type: "opxdr-env-key", key: gmapsKey }, "*");
        } else {
          el.contentWindow.postMessage({ type: "opxdr-init-cesium" }, "*");
        }
      } catch {}
    };
    el.addEventListener("load", onLoad);
    if (el.contentDocument && el.contentDocument.readyState === "complete") onLoad();
    return () => el.removeEventListener("load", onLoad);
  }, []);

  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 9999 }}>
      <iframe
        ref={iframeRef}
        src="/geo.html"
        style={{
          width: "100%",
          height: "100%",
          border: "none",
          display: "block",
          background: "#000810",
        }}
      />
      <div
        onClick={goBack}
        style={{
          position: "absolute",
          bottom: 52,
          right: 14,
          background: "rgba(0,18,40,0.88)",
          border: "1px solid rgba(0,100,200,0.35)",
          color: "#38bdf8",
          padding: "5px 11px",
          borderRadius: 6,
          cursor: "pointer",
          fontSize: "0.65rem",
          fontFamily: "'Oxanium', monospace",
          zIndex: 10000,
          display: "flex",
          alignItems: "center",
          gap: 5,
          backdropFilter: "blur(4px)",
        }}
      >
        ← OPXDR
      </div>
    </div>
  );
}
