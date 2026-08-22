import { useContext, useState } from "react";
import { OpxdrContext } from "../App";
import { Folder, Eye, Copy, X, Search, Send } from "../lib/icons";

const slacked = new Set();

export default function Documents() {
  const { savedDocs, setSavedDocs } = useContext(OpxdrContext);
  const [search, setSearch] = useState("");
  const [viewDoc, setViewDoc] = useState(null);
  const [sending, setSending] = useState(null);
  const [toast, setToast] = useState(null);

  function showToast(msg, ok = true) {
    setToast({ msg, ok });
    setTimeout(() => setToast(null), 3500);
  }

  async function shareToSlack(doc) {
    if (slacked.has(doc.id)) {
      showToast("Already shared to Slack");
      return;
    }
    setSending(doc.id);
    try {
      const res = await fetch("/api/slack/share", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ doc }),
      });
      if (!res.ok) {
        const err = await res.text().catch(() => "");
        throw new Error(err || `Slack responded ${res.status}`);
      }
      slacked.add(doc.id);
      showToast("Sent to Slack");
    } catch (e) {
      showToast(e.message, false);
    } finally {
      setSending(null);
    }
  }

  const filtered = savedDocs.filter(d =>
    !search || (d.title || "").toLowerCase().includes(search.toLowerCase())
  );

  function exportText(doc) {
    if (doc.messages) return doc.messages.filter(m => m.role === "assistant").map(m => m.content).join("\n\n---\n\n");
    return doc.report || "";
  }

  function deleteDoc(id) {
    setSavedDocs(savedDocs.filter(d => d.id !== id));
  }

  return (
    <div className="p-5">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-xl font-extrabold text-ink-0 flex items-center gap-2">
            <Folder size={20} className="text-brand-accent" /> Documents
          </h1>
          <p className="text-2xs text-ink-3 mt-0.5">{savedDocs.length} saved investigations and reports</p>
        </div>
        <div className="relative">
          <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-ink-3" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search documents..."
            className="bg-bg-2 border border-border rounded-md pl-8 pr-3 py-1.5 text-xs text-ink-0 w-72 focus:border-brand outline-none"
          />
        </div>
      </div>

      {filtered.length === 0 && (
        <div className="panel p-12 text-center">
          <Folder size={32} className="mx-auto mb-3 text-ink-4 opacity-50" />
          <div className="text-sm text-ink-2 mb-1">No saved documents yet</div>
          <div className="text-2xs text-ink-3">
            Use the Save button on Agent Investigations to preserve findings here.
          </div>
        </div>
      )}

      <div className="space-y-3">
        {filtered.map(doc => (
          <div key={doc.id} className="panel p-4 flex items-start gap-4 hover:bg-bg-2 transition-colors">
            <div className="w-1 self-stretch rounded-full bg-brand-accent flex-shrink-0" />
            <div className="flex-1 min-w-0">
              <div className="flex items-start justify-between mb-2">
                <div>
                  <h3 className="text-sm font-bold text-ink-0">{doc.title}</h3>
                  <div className="text-3xs text-ink-3 mt-0.5">
                    {new Date(doc.created).toLocaleString()} · <code className="font-mono">{doc.id}</code>
                  </div>
                </div>
                <div className="flex gap-2">
                  <button onClick={() => setViewDoc(doc)} className="btn btn-outline text-2xs">
                    <Eye size={12} /> View
                  </button>
                  <button onClick={() => shareToSlack(doc)} disabled={sending === doc.id} className="btn btn-ghost text-2xs text-brand">
                    {sending === doc.id ? <span className="animate-spin inline-block">&#9696;</span> : <Send size={12} />} Slack
                  </button>
                  <button onClick={() => navigator.clipboard?.writeText(exportText(doc))} className="btn btn-ghost text-2xs">
                    <Copy size={12} /> Copy
                  </button>
                  <button onClick={() => deleteDoc(doc.id)} className="btn btn-ghost text-2xs text-bad">
                    <X size={12} />
                  </button>
                </div>
              </div>
              {doc.alert && (
                <div className="flex items-center gap-2 text-2xs">
                  <span className={`badge ${
                    doc.alert.severity === "CRITICAL" ? "badge-critical" :
                    doc.alert.severity === "HIGH" ? "badge-high" : "badge-medium"
                  }`}>{doc.alert.severity}</span>
                  <code className="text-ink-3 font-mono">{doc.alert.id}</code>
                  <span className="text-ink-2 truncate">{doc.alert.ruleName}</span>
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      {toast && (
        <div className={`fixed bottom-6 right-6 z-50 px-4 py-2.5 rounded-lg shadow-lg text-xs font-medium transition-all ${
          toast.ok ? "bg-bg-2 text-ink-1 border border-border" : "bg-bad/10 text-bad border border-bad/30"
        }`}>
          {toast.ok ? "✓ " : "✗ "}{toast.msg}
        </div>
      )}

      {viewDoc && (
        <div className="fixed inset-0 bg-black/85 z-50 flex items-center justify-center p-4">
          <div className="bg-bg-1 border border-border rounded-xl w-full max-w-4xl max-h-[92vh] flex flex-col overflow-hidden">
            <div className="px-5 py-3 border-b border-border flex items-center justify-between">
              <div>
                <div className="text-sm font-bold text-ink-0">{viewDoc.title}</div>
                <div className="text-3xs text-ink-3 font-mono mt-0.5">
                  {new Date(viewDoc.created).toLocaleString()}
                </div>
              </div>
              <div className="flex gap-2">
                <button onClick={() => shareToSlack(viewDoc)} disabled={sending === viewDoc.id} className="btn btn-outline text-brand">
                  {sending === viewDoc.id ? <span className="animate-spin inline-block">&#9696;</span> : <Send size={12} />} Slack
                </button>
                <button onClick={() => navigator.clipboard?.writeText(exportText(viewDoc))} className="btn btn-outline">
                  <Copy size={12} /> Copy
                </button>
                <button onClick={() => setViewDoc(null)} className="btn btn-ghost">
                  <X size={14} />
                </button>
              </div>
            </div>
            <div className="flex-1 overflow-y-auto p-5">
              {viewDoc.report ? (
                <pre className="whitespace-pre-wrap text-sm text-ink-1 font-sans leading-relaxed">{viewDoc.report}</pre>
              ) : viewDoc.messages ? (
                <div className="space-y-3">
                  {viewDoc.messages.map((m, i) => (
                    <div key={i} className={`px-4 py-2.5 rounded-lg ${
                      m.role === "user" ? "bg-brand/10 border border-brand/30" : "bg-bg-2 border border-border"
                    }`}>
                      <div className="text-3xs text-ink-3 mb-1 uppercase tracking-wider font-mono">{m.role}</div>
                      <pre className="whitespace-pre-wrap text-sm text-ink-1 font-sans leading-relaxed">{m.content}</pre>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-ink-3 text-sm py-8 text-center">No content</div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
