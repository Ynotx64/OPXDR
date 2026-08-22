import { useContext, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { OpxdrContext } from "../App";
import { Eye, Send, Sparkles, Save, Copy } from "../lib/icons";
import { callAgent, timeAgo } from "../lib/api";

const SYS_INVESTIGATE = `You are an expert SOC analyst. Given a Wazuh alert, produce:
1. Severity assessment (with reasoning)
2. MITRE ATT&CK mapping
3. Likely attack chain
4. Immediate IR steps (numbered)
5. Hunt queries (KQL or osquery if applicable)
Format as clean markdown.`;

function formatAlert(a) {
  return `# Alert Context

| Field | Value |
|---|---|
| ID | \`${a.id}\` |
| Rule | ${a.ruleName} |
| Severity | ${a.severity} (level ${a.level}) |
| Tactic | ${a.tactic} |
| MITRE | ${a.mitre} |
| Host | \`${a.host}\` |
| Src IP | \`${a.srcIp}\` |
| Dst IP | \`${a.dstIp}\` |
| Account | \`${a.account}\` |
| Time | ${a.time} |
| IOCs | ${(a.iocs || []).map(i => `\`[${i.t}] ${i.v}\``).join(", ") || "—"} |
`;
}

export default function Investigations() {
  const { alerts, savedDocs, setSavedDocs } = useContext(OpxdrContext);
  const [params, setParams] = useSearchParams();
  const alertId = params.get("alert");
  const focusAlert = alerts.find(a => a.id === alertId);

  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [streaming, setStreaming] = useState(false);
  const scrollRef = useRef(null);

  useEffect(() => {
    if (focusAlert && messages.length === 0) {
      const ctx = formatAlert(focusAlert);
      setMessages([
        { role: "user", content: `${ctx}\n\nInvestigate this alert.` },
      ]);
      runAgent(`${ctx}\n\nInvestigate this alert.`);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [alertId]);

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages, streaming]);

  async function runAgent(promptText) {
    setStreaming(true);
    const conversation = [
      ...messages.map(m => ({ role: m.role, content: m.content })),
      { role: "user", content: promptText },
    ];
    setMessages(m => [...m, { role: "assistant", content: "" }]);
    await callAgent("investigate", conversation, (chunk) => {
      setMessages(m => {
        const copy = [...m];
        copy[copy.length - 1] = { role: "assistant", content: chunk };
        return copy;
      });
    }, { system: SYS_INVESTIGATE });
    setStreaming(false);
  }

  function send() {
    if (!input.trim() || streaming) return;
    const txt = input.trim();
    setInput("");
    setMessages(m => [...m, { role: "user", content: txt }]);
    runAgent(txt);
  }

  function saveInvestigation() {
    if (messages.length < 2) return;
    const report = messages.filter(m => m.role === "assistant").map(m => m.content).join("\n\n---\n\n");
    const doc = {
      id: `INV-${Date.now()}`,
      title: focusAlert ? `Investigation: ${focusAlert.ruleName}` : "Investigation",
      alert: focusAlert || null,
      messages,
      report,
      created: new Date().toISOString(),
    };
    setSavedDocs([doc, ...savedDocs]);
    alert(`Saved as ${doc.id}`);
  }

  return (
    <div className="p-5 max-w-5xl mx-auto h-full flex flex-col">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-extrabold text-ink-0 flex items-center gap-2">
            <Eye size={20} className="text-brand-accent" /> Agent Investigations
          </h1>
          <p className="text-2xs text-ink-3 mt-0.5">
            {focusAlert ? `Investigating ${focusAlert.id}` : "Chat with the OPXDR agent"}
          </p>
        </div>
        <button onClick={saveInvestigation} disabled={messages.length < 2} className="btn btn-outline gap-1.5 disabled:opacity-40">
          <Save size={14} /> Save
        </button>
      </div>

      {focusAlert && (
        <div className="panel p-3 mb-3 text-xs font-mono">
          <div className="flex items-center gap-2 mb-1">
            <span className={`badge badge-${focusAlert.severity === "CRITICAL" ? "critical" : focusAlert.severity === "HIGH" ? "high" : "medium"}`}>
              {focusAlert.severity}
            </span>
            <span className="text-ink-1 font-semibold">{focusAlert.ruleName}</span>
            <span className="text-ink-3 ml-auto">{timeAgo(focusAlert.time)}</span>
          </div>
          <div className="grid grid-cols-4 gap-3 text-2xs text-ink-2">
            <div><span className="text-ink-3">host:</span> {focusAlert.host}</div>
            <div><span className="text-ink-3">src:</span> {focusAlert.srcIp}</div>
            <div><span className="text-ink-3">account:</span> {focusAlert.account}</div>
            <div><span className="text-ink-3">tactic:</span> {focusAlert.tactic}</div>
          </div>
        </div>
      )}

      <div ref={scrollRef} className="panel flex-1 overflow-y-auto p-4 mb-3 space-y-4">
        {messages.length === 0 && (
          <div className="text-center text-ink-3 py-12">
            <Sparkles size={32} className="mx-auto mb-3 opacity-40" />
            <p className="text-sm">Send a prompt or open this page with <code className="text-brand-accent">?alert=DET-...</code> to begin.</p>
          </div>
        )}
        {messages.map((m, i) => (
          <div key={i} className={`flex gap-3 ${m.role === "user" ? "justify-end" : ""}`}>
            {m.role !== "user" && (
              <div className="w-7 h-7 rounded-md bg-brand-accent/20 border border-brand-accent/40 flex items-center justify-center flex-shrink-0">
                <Sparkles size={13} className="text-brand-accent" />
              </div>
            )}
            <div className={`max-w-3xl px-4 py-2.5 rounded-lg ${
              m.role === "user" ? "bg-brand/20 border border-brand/30 text-ink-0" : "bg-bg-2 border border-border text-ink-1"
            }`}>
              <pre className="whitespace-pre-wrap font-sans text-sm leading-relaxed">{m.content || (streaming && i === messages.length - 1 ? "..." : "")}</pre>
            </div>
          </div>
        ))}
      </div>

      <div className="flex gap-2">
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === "Enter" && !e.shiftKey && (e.preventDefault(), send())}
          placeholder={streaming ? "Agent is responding..." : "Ask the OPXDR agent..."}
          disabled={streaming}
          className="flex-1 bg-bg-2 border border-border rounded-md px-4 py-2.5 text-sm placeholder:text-ink-3 focus:border-brand focus:outline-none"
        />
        <button onClick={send} disabled={!input.trim() || streaming} className="btn btn-brand disabled:opacity-40">
          <Send size={14} /> Send
        </button>
      </div>
    </div>
  );
}
