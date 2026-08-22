import { Network, Box, Layers, Server, Lock, Workflow, PlayCircle, FileText } from "../lib/icons";

function Placeholder({ title, icon: Icon, desc }) {
  return (
    <div className="p-5">
      <div className="mb-4">
        <h1 className="text-xl font-extrabold text-ink-0 flex items-center gap-2">
          <Icon size={20} className="text-brand-accent" /> {title}
        </h1>
        <p className="text-2xs text-ink-3 mt-0.5">{desc}</p>
      </div>
      <div className="panel p-12 text-center">
        <Icon size={32} className="mx-auto mb-3 text-ink-4 opacity-50" />
        <div className="text-sm text-ink-2 mb-1">{title} surface coming soon</div>
        <div className="text-2xs text-ink-3">Backend hooks exist · UI not yet built</div>
      </div>
    </div>
  );
}

export const ThreatFeeds = () => <Placeholder title="Honeypot Threat Intelligence" icon={Network} desc="Decoy services, attacker telemetry, and server lure coverage" />;
export const Indicators = () => <Placeholder title="Indicators (IOCs)" icon={Box} desc="IPs, domains, hashes, certificates" />;
export const AttackPatterns = () => <Placeholder title="Attack Patterns" icon={Layers} desc="MITRE ATT&CK technique browser" />;
export const AssetInventory = () => <Placeholder title="Asset Inventory" icon={Server} desc="Wazuh agents, endpoints, network devices" />;
export const NetworkMap = () => <Placeholder title="Network Map" icon={Network} desc="Topology and segment visualization" />;
export const Vulnerabilities = () => <Placeholder title="Vulnerabilities" icon={Lock} desc="CVE tracking and patch status" />;
export const Playbooks = () => <Placeholder title="Playbooks" icon={Workflow} desc="IR runbooks and Ansible automation" />;
export const Responses = () => <Placeholder title="Response Actions" icon={PlayCircle} desc="Containment, eradication, recovery" />;
export const Integrations = () => <Placeholder title="Integrations" icon={Network} desc="Slack, SIEM, EDR, SOAR" />;
export const Reports = () => <Placeholder title="Reports" icon={FileText} desc="Executive dashboards and compliance" />;
