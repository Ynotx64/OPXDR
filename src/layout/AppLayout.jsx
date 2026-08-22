import { Outlet } from "react-router-dom";
import { useContext } from "react";
import Sidebar from "./Sidebar";
import TopBar from "./TopBar";
import LiveFeedTicker from "./LiveFeedTicker";
import { OpxdrContext } from "../App";

export default function AppLayout() {
  const { alerts, backendStatus } = useContext(OpxdrContext);
  return (
    <div className="h-screen flex bg-bg-0">
      <Sidebar alertCount={alerts.length} />
      <div className="flex-1 flex flex-col min-w-0">
        <TopBar backendStatus={backendStatus} alertCount={alerts.length} />
        <main className="flex-1 overflow-y-auto bg-bg-0">
          <Outlet />
        </main>
        <LiveFeedTicker alerts={alerts} />
      </div>
    </div>
  );
}
