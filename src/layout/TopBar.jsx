import { useState, useEffect } from "react";
import { Search, Bell, FileText, Settings, Sparkles, User, Database } from "../lib/icons";

export default function TopBar({ backendStatus = "ok", alertCount = 0 }) {
  const [time, setTime] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  return (
    <header className="h-[60px] bg-bg-1 border-b border-border flex items-center px-5 gap-4 flex-shrink-0">
      {/* Mode pills */}
      <div className="flex items-center gap-1.5">
        <span className="px-2.5 py-1 rounded-md bg-bg-2 border border-border text-2xs font-semibold uppercase tracking-wider text-ink-0">
          Global View
        </span>
        <span className="px-2.5 py-1 rounded-md text-2xs font-semibold uppercase tracking-wider text-ink-3 flex items-center gap-1.5">
          <span className="live-dot" /> Live Intelligence
        </span>
      </div>

      {/* Search */}
      <div className="flex-1 max-w-2xl relative">
        <Search size={14} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-ink-3 pointer-events-none" />
        <input
          type="text"
          placeholder="Search places, addresses, IPs, domains..."
          className="w-full bg-bg-2 border border-border rounded-md pl-10 pr-16 py-2 text-sm
                     placeholder:text-ink-3 text-ink-0 focus:border-brand focus:outline-none
                     transition-colors"
        />
        <kbd className="absolute right-3 top-1/2 -translate-y-1/2 text-3xs text-ink-3 bg-bg-3
                       border border-border px-1.5 py-0.5 rounded font-mono">
          CTRL K
        </kbd>
      </div>

      {/* Right cluster */}
      <div className="flex items-center gap-2">
        <button className="btn btn-accent gap-1.5">
          <Sparkles size={14} />
          AI Assistant
        </button>
        <IconButton icon={FileText} />
        <IconButton icon={Bell} dot={alertCount > 0} />
        <IconButton icon={Settings} />
        <div className="w-px h-6 bg-border mx-1" />
        <div className="flex items-center gap-2 px-2">
          <div className="w-8 h-8 rounded-md bg-bg-3 border border-border flex items-center justify-center text-ink-2 text-xs font-semibold">
            SO
          </div>
        </div>
      </div>
    </header>
  );
}

function IconButton({ icon: Icon, dot }) {
  return (
    <button className="relative w-9 h-9 rounded-md hover:bg-bg-2 flex items-center justify-center text-ink-2 hover:text-ink-0 transition-colors">
      <Icon size={16} />
      {dot && <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-sev-high rounded-full" />}
    </button>
  );
}
