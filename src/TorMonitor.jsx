import { useCallback, useEffect, useRef } from "react";

export default function TorMonitor() {
  const iframeRef = useRef(null);
  const goBack = useCallback(() => {
    window.dispatchEvent(new CustomEvent("opxdr-nav", { detail: "registry" }));
  }, []);

  useEffect(() => {
    const el = iframeRef.current;
    if (!el) return;
    const onLoad = () => {
      try {
        el.contentWindow.postMessage({ type: "opxdr-tor-ready" }, "*");
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
        src="/opx-tor.html"
        style={{
          width: "100%",
          height: "100%",
          border: "none",
          display: "block",
          background: "#0a0b0d",
        }}
      />
      <div
        onClick={goBack}
        style={{
          position: "absolute",
          bottom: 52,
          right: 14,
          background: "rgba(10,11,13,0.88)",
          border: "1px solid rgba(0,255,140,0.25)",
          color: "#00ff8c",
          padding: "5px 11px",
          borderRadius: 6,
          cursor: "pointer",
          fontSize: "0.65rem",
          fontFamily: "'JetBrains Mono', monospace",
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
