import React, { useState, useEffect, useRef } from "react";
import GeoIntel from "./GeoIntel";
import TorMonitor from "./TorMonitor";

// ─── STORAGE ──────────────────────────────────────────────────────────────────
// Swap 1: window.storage → localStorage
const SK_RULES = "wazuh_soc_rules_v4";
const SK_ALERTS = "wazuh_soc_alerts_v4";
const SK_DOCS   = "opxdr_documents_v1";
async function dbLoad(k) { try { const r = localStorage.getItem(k); return r ? JSON.parse(r) : null; } catch { return null; } }
async function dbSave(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} }

// ─── HELPERS ──────────────────────────────────────────────────────────────────
const pad = (n, w=2) => String(n).padStart(w,"0");
function genAlertId(prefix="DET") {
  const n=new Date(); return `${prefix}-${n.getFullYear()}${pad(n.getMonth()+1)}${pad(n.getDate())}-${String(Math.floor(Math.random()*9000)+1000)}`;
}
function genIRId() {
  const n=new Date(); return `IR-${n.getFullYear()}${pad(n.getMonth()+1)}${pad(n.getDate())}-${pad(n.getHours())}${pad(n.getMinutes())}${pad(n.getSeconds())}`;
}
function ts() { return new Date().toLocaleTimeString(); }

function deriveMeta(t) {
  const s=t.toLowerCase();
  if(/initial.access|phish|exploit/.test(s))        return "Initial Access";
  if(/execut|command|script|shell/.test(s))          return "Execution";
  if(/escalat|privilege|sudo|admin/.test(s))         return "Privilege Escalation";
  if(/lateral|rdp|smb|wmi|pass.hash/.test(s))        return "Lateral Movement";
  if(/credential|password|spray|brute/.test(s))      return "Credential Access";
  if(/discover|scan|enum/.test(s))                   return "Discovery";
  if(/c2|beacon|command.control/.test(s))            return "Command & Control";
  if(/exfil|stage|upload|transfer/.test(s))          return "Exfiltration";
  if(/collect|mailbox|data/.test(s))                 return "Collection";
  if(/persist|startup|service|registry/.test(s))     return "Persistence";
  if(/impact|ransom|ddos|wipe/.test(s))              return "Impact";
  return "Defense Evasion";
}
function sevFromLevel(l) { const n=parseInt(l); if(n>=15)return"CRITICAL"; if(n>=12)return"HIGH"; if(n>=7)return"MEDIUM"; return"LOW"; }

function parseXML(xmlText) {
  const errors=[],extracted=[];
  if(!xmlText.includes("<rule")){errors.push("No <rule> elements found.");return{extracted,errors};}
  const re=/<rule\s+id="(\d+)"[^>]*level="(\d+)"[^>]*>([\s\S]*?)<\/rule>/g; let m;
  while((m=re.exec(xmlText))!==null){
    const[,ruleId,level,body]=m;
    const desc=(body.match(/<description>([\s\S]*?)<\/description>/)?.[1]||"").trim();
    const group=(body.match(/<group>([\s\S]*?)<\/group>/)?.[1]||"").trim();
    const mitre=[...body.matchAll(/<id>(T\d+(?:\.\d+)?)<\/id>/g)].map(x=>x[1]).join(",")||"T1059";
    const decoded=(body.match(/<decoded_as>([\s\S]*?)<\/decoded_as>/)?.[1]||"").trim();
    const fld=body.match(/<field\s+name="([^"]+)"[^>]*>([\s\S]*?)<\/field>/);
    const ioc=fld?`${fld[1]}:${fld[2].trim()}`:"";
    const tactic=deriveMeta(group+" "+desc);
    extracted.push({wazuhRuleId:ruleId,level:parseInt(level),severity:sevFromLevel(level),description:desc,group,mitre,tactic,decoded,ioc});
  }
  if(!extracted.length)errors.push("No valid <rule id=\"...\"> blocks found.");
  return{extracted,errors};
}

// ─── PLAYBOOK TEMPLATES ───────────────────────────────────────────────────────
const PB_TEMPLATES = {
  "Initial Access":{ steps:[
    {phase:"IDENTIFICATION",action:"Verify alert — check Wazuh rule ID and log origin",cmd:`curl -k -X GET 'https://localhost:55000/alerts?rule.id={RULE_ID}&limit=20' \\\n  -H 'Authorization: Bearer $TOKEN'`},
    {phase:"CONTAINMENT",action:"Block source IP at perimeter firewall",cmd:"ansible-playbook containment_block_src.yml -e 'src_ip={SRC_IP}'"},
    {phase:"CONTAINMENT",action:"Isolate affected host from network segment",cmd:"ansible-playbook triage_collect.yml -e 'target_host={HOST}'"},
    {phase:"ERADICATION",action:"Rotate credentials for accessed accounts",cmd:"net user {ACCOUNT} /domain /active:no"},
    {phase:"RECOVERY",action:"Restore from last known-good snapshot",cmd:"ansible-playbook validate_pipeline.yml -e 'host={HOST}'"},
    {phase:"CLOSE",action:"Generate IR artifact and close case",cmd:"ansible-playbook close_case.yml -e 'ir_id={IR_ID}'"},
  ]},
  "Lateral Movement":{ steps:[
    {phase:"IDENTIFICATION",action:"Pull all auth events for source account",cmd:"grep '{ACCOUNT}' /var/ossec/logs/alerts/alerts.json | jq '.data.dstip' | sort -u"},
    {phase:"IDENTIFICATION",action:"Map all servers touched by compromised account",cmd:"curl -k 'https://localhost:55000/alerts?agent.name={AGENT}&rule.groups=authentication&limit=50'"},
    {phase:"CONTAINMENT",action:"Disable compromised service account immediately",cmd:"net user {ACCOUNT} /domain /active:no\nansible-playbook containment_block_src.yml -e 'account={ACCOUNT}'"},
    {phase:"CONTAINMENT",action:"Isolate affected servers",cmd:"ansible-playbook triage_collect.yml -e 'target_hosts={HOST_LIST}'"},
    {phase:"ERADICATION",action:"Hunt for persistence on touched servers",cmd:"ansible-playbook validate_correlation.yml -e 'search_account={ACCOUNT}'"},
    {phase:"CLOSE",action:"File IR artifact — notify CISO",cmd:"ansible-playbook close_case.yml -e 'ir_id={IR_ID} severity=CRITICAL'"},
  ]},
  "Credential Access":{ steps:[
    {phase:"IDENTIFICATION",action:"Identify targeted accounts — check spray pattern",cmd:"cat /var/ossec/logs/alerts/alerts.json | jq 'select(.rule.id==\"{RULE_ID}\")' | jq '.data.srcuser' | sort | uniq -c | sort -rn"},
    {phase:"CONTAINMENT",action:"Lock targeted privileged accounts",cmd:"net user {ACCOUNT} /domain /active:no"},
    {phase:"CONTAINMENT",action:"Block attacking IPs at WAF and perimeter",cmd:"ansible-playbook containment_block_src.yml -e 'src_ip={SRC_IP}'"},
    {phase:"ERADICATION",action:"Force password reset on all targeted accounts",cmd:"Set-ADUser {ACCOUNT} -ChangePasswordAtLogon $true"},
    {phase:"RECOVERY",action:"Re-enable accounts after reset + MFA verify",cmd:"ansible-playbook validate_pipeline.yml"},
    {phase:"CLOSE",action:"Close case — log IOCs to threat intel",cmd:"ansible-playbook close_case.yml -e 'ir_id={IR_ID}'"},
  ]},
  "Command & Control":{ steps:[
    {phase:"IDENTIFICATION",action:"Capture and analyze beacon traffic",cmd:"ansible-playbook ir_suricata_alert.yml -e 'alert_id={ALERT_ID}'\ntcpdump -i any -w /tmp/c2_{IR_ID}.pcap host {SRC_IP}"},
    {phase:"CONTAINMENT",action:"Block C2 IPs/domains at DNS and firewall",cmd:"ansible-playbook containment_block_src.yml -e 'src_ip={C2_IP} add_dns_block=true'"},
    {phase:"CONTAINMENT",action:"Isolate beaconing host",cmd:"ansible-playbook triage_collect.yml -e 'target_host={HOST}'"},
    {phase:"ERADICATION",action:"Remove implant — hunt persistence artifacts",cmd:"ansible-playbook validate_correlation.yml -e 'host={HOST} hunt_c2=true'"},
    {phase:"RECOVERY",action:"Reimage host if implant unconfirmed removed",cmd:"# Initiate reimage workflow via ITSM"},
    {phase:"CLOSE",action:"Submit C2 IOCs to threat intel — close case",cmd:"ansible-playbook close_case.yml -e 'ir_id={IR_ID} submit_iocs=true'"},
  ]},
  "Exfiltration":{ steps:[
    {phase:"IDENTIFICATION",action:"Identify data scope and exfil destination",cmd:"cat /var/ossec/logs/alerts/alerts.json | jq 'select(.rule.groups|contains(\"exfiltration\"))' | jq '{src:.data.srcip,dst:.data.dstip,bytes:.data.bytes}'"},
    {phase:"CONTAINMENT",action:"Block egress to exfil destination",cmd:"ansible-playbook containment_block_src.yml -e 'dst_ip={DST_IP} direction=egress'"},
    {phase:"CONTAINMENT",action:"Capture full packet data for evidence",cmd:"tcpdump -i any -w /evidence/exfil_{IR_ID}.pcap host {DST_IP}"},
    {phase:"ERADICATION",action:"Identify and remove staging scripts",cmd:"find / -name '*.py' -o -name '*.sh' -newer /tmp/.baseline 2>/dev/null"},
    {phase:"RECOVERY",action:"Assess data exposure — trigger breach notification if PII",cmd:"# Escalate to legal/DPO if regulated data confirmed exfiltrated"},
    {phase:"CLOSE",action:"File IR artifact — notify DPO if required",cmd:"ansible-playbook close_case.yml -e 'ir_id={IR_ID} notify_dpo=true'"},
  ]},
};
function getPBTemplate(tactic){ return PB_TEMPLATES[tactic]||PB_TEMPLATES["Initial Access"]; }

function pbToYAML(pb, rule) {
  const steps = pb.steps.map((s,i)=>
`  - id: step_${String(i+1).padStart(2,"0")}
    phase: ${s.phase}
    action: "${s.action}"
    status: ${s.done?"completed":"pending"}
    command: |
      ${s.cmd.split("\n").join("\n      ")}
    notes: "${s.notes||""}"`
  ).join("\n\n");
  const iocs = pb.iocs?.filter(ioc=>ioc.value).map(ioc=>`  - type: ${ioc.type}\n    value: "${ioc.value}"`).join("\n") || "  []";
  const notifs = Object.entries(pb.notifications||{}).filter(([,v])=>v).map(([k])=>k).join(", ")||"none";
  return `# IR Playbook — Generated by OPXDR
# Case: ${pb.irId} | Rule: ${rule?.id||"CUSTOM"} | ${pb.severity}

playbook:
  id: "${pb.irId}"
  title: "${pb.title}"
  severity: ${pb.severity}
  tactic: "${pb.tactic}"
  analyst: "${pb.analyst||"unassigned"}"
  created: "${new Date().toISOString()}"
  rule_id: "${rule?.id||""}"
  rule_name: "${rule?.name||""}"
  mitre: "${rule?.mitre||""}"

notifications:
  targets: [${notifs}]

iocs:
${iocs}

response_steps:
${steps}

close:
  command: "ansible-playbook close_case.yml -e 'ir_id=${pb.irId}'"
  status: ${pb.steps.every(s=>s.done)?"completed":"in_progress"}
`;
}

// ─── STATIC REGISTRY ──────────────────────────────────────────────────────────
const STATIC_REG = {
  honeypot:{label:"Honeypot Cluster",color:"#f97316",icon:"🍯",rules:[
    {id:"HP-010",file:"010-cowrie_rules.xml",         name:"Cowrie SSH/Telnet Honeypot",      tactic:"Initial Access",       mitre:"T1110",       severity:"HIGH"},
    {id:"HP-030",file:"030-heralding_rules.xml",      name:"Heralding Credential Honeypot",   tactic:"Credential Access",    mitre:"T1078",       severity:"CRITICAL"},
    {id:"HP-050",file:"050-mailoney_rules.xml",        name:"Mailoney SMTP Trap",              tactic:"Phishing",             mitre:"T1566",       severity:"HIGH"},
    {id:"HP-090",file:"090-ciscoasa_rules.xml",        name:"CiscoASA Emulator",               tactic:"Initial Access",       mitre:"T1190",       severity:"CRITICAL"},
    {id:"HP-110",file:"110-conpot_rules.xml",          name:"Conpot ICS/SCADA Honeypot",       tactic:"Initial Access",       mitre:"T1190",       severity:"CRITICAL"},
    {id:"HP-180",file:"180-correlation_rules.xml",     name:"Cross-Honeypot Correlation",      tactic:"Multiple Stages",      mitre:"CORR",        severity:"CRITICAL"},
  ]},
  aptpack:{label:"APTPACK Threat Packs",color:"#ef4444",icon:"☠️",rules:[
    {id:"AP-IA",  file:"APTPACK-IA/ia-wazuh.xml",      name:"Initial Access Detection",        tactic:"Initial Access",       mitre:"T1566,T1190,T1078",severity:"CRITICAL"},
    {id:"AP-EXEC",file:"APTPACK-EXEC/exec-wazuh.xml",  name:"Execution — Encoded Cmd & Eval",  tactic:"Execution",            mitre:"T1059,T1027",       severity:"HIGH"},
    {id:"AP-PE",  file:"APTPACK-PE/pe-wazuh.xml",      name:"Privilege Escalation & Persist",  tactic:"Privilege Escalation", mitre:"T1068,T1547",       severity:"CRITICAL"},
    {id:"AP-DISC",file:"APTPACK-DISC/disc-wazuh.xml",  name:"Discovery — Net Scan & Low/Slow", tactic:"Discovery",            mitre:"T1046,T1018",       severity:"MEDIUM"},
    {id:"AP-CA",  file:"APTPACK-CA/ca-wazuh.xml",      name:"C2 Beacon & Jitter",              tactic:"Command & Control",    mitre:"T1071,T1573",       severity:"CRITICAL"},
    {id:"AP-STG", file:"APTPACK-STAGE/stage-wazuh.xml",name:"Staging — Upload & Chunking",     tactic:"Exfiltration",         mitre:"T1030,T1041",       severity:"HIGH"},
  ]},
  apt31:{label:"APT31 (Zirconium)",color:"#a855f7",icon:"🐼",rules:[
    {id:"A31-03",file:"apt31_password_spray_privileged_accounts.yml",  name:"Password Spray — Privileged Accts",tactic:"Credential Access",    mitre:"T1110.003",  severity:"CRITICAL"},
    {id:"A31-05",file:"apt31_targeted_phishing_to_privileged_signin.yml",name:"Phishing → Privileged Sign-in",  tactic:"Initial Access",       mitre:"T1566,T1078",severity:"CRITICAL"},
  ]},
  ifrag:{label:"iFrag-DHV (RDP)",color:"#06b6d4",icon:"🖥️",rules:[
    {id:"RDP-03",file:"windows_rdp_bruteforce.yml",            name:"Windows RDP Bruteforce",           tactic:"Credential Access",    mitre:"T1110.001",  severity:"CRITICAL"},
    {id:"RDP-04",file:"windows_rdp_success_after_failures.yml",name:"RDP Success After Failures",       tactic:"Initial Access",       mitre:"T1078",      severity:"CRITICAL"},
  ]},
  edge:{label:"Edge Appliance / VPN",color:"#38bdf8",icon:"🔀",rules:[
    {id:"EDG-03",file:"edge-logging-disabled-or-redirected.yml",name:"Logging Disabled/Redirected",    tactic:"Defense Evasion",      mitre:"T1562.002",  severity:"CRITICAL"},
    {id:"EDG-04",file:"edge-unexpected-egress.yml",             name:"Unexpected Egress Traffic",       tactic:"Exfiltration",         mitre:"T1048",      severity:"HIGH"},
  ]},
  malware:{label:"Malware (YARA)",color:"#fb7185",icon:"🦠",rules:[
    {id:"MAL-01",file:"detect_Redline_Stealer.yar",             name:"Redline Stealer",                 tactic:"Credential Access",    mitre:"T1555,T1539",severity:"CRITICAL"},
  ]},
};

// ─── UI ATOMS ─────────────────────────────────────────────────────────────────
const SEV={CRITICAL:{bg:"#ff000018",border:"#ff4444",text:"#ff6060"},HIGH:{bg:"#ff880018",border:"#ff8800",text:"#ffaa44"},MEDIUM:{bg:"#ffff0018",border:"#cccc00",text:"#dddd44"},LOW:{bg:"#22c55e18",border:"#22c55e",text:"#4ade80"}};
const TACS={"Initial Access":"#f97316","Execution":"#ef4444","Privilege Escalation":"#a855f7","Credential Access":"#eab308","Discovery":"#38bdf8","Lateral Movement":"#06b6d4","Command & Control":"#22c55e","C2":"#22c55e","Exfiltration":"#fb7185","Collection":"#e879f9","Defense Evasion":"#64748b","Multiple Stages":"#f43f5e","Multiple":"#f43f5e","Persistence":"#d97706","Reconnaissance":"#84cc16","Phishing":"#f97316","Resource Dev":"#8b5cf6","Impact":"#dc2626"};
const PH_COL={IDENTIFICATION:"#38bdf8",CONTAINMENT:"#f97316",ERADICATION:"#ef4444",RECOVERY:"#22c55e",CLOSE:"#a78bfa"};
function SB({l}){const s=SEV[l]||SEV.MEDIUM;return<span style={{background:s.bg,border:`1px solid ${s.border}`,color:s.text,padding:"1px 8px",borderRadius:3,fontSize:"0.66rem",fontFamily:"monospace",fontWeight:700,letterSpacing:1}}>{l}</span>;}
function TB({t}){const c=TACS[t]||"#6b7280";return<span style={{background:c+"20",border:`1px solid ${c}55`,color:c,padding:"1px 7px",borderRadius:3,fontSize:"0.65rem",fontFamily:"monospace",whiteSpace:"nowrap"}}>{t}</span>;}
const inp=(x={})=>({background:"#060d1a",border:"1px solid #1e293b",borderRadius:6,color:"#e2e8f0",padding:"7px 11px",fontSize:"0.75rem",fontFamily:"'IBM Plex Mono',monospace",outline:"none",width:"100%",...x});
const lbl={color:"#475569",fontSize:"0.67rem",fontFamily:"monospace",letterSpacing:1,display:"block",marginBottom:3};

// ─── CLAUDE API ───────────────────────────────────────────────────────────────
// Swap 2: direct Anthropic fetch → backend proxy at /api/claude
async function claude(system, messages, onChunk) {
  const res = await fetch("/api/claude", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ system, messages, max_tokens: 1000, stream: true }),
  });
  if (!res.ok) {
    const errText = await res.text();
    const fallback = `[AI unavailable: ${res.status}] ${errText}`;
    onChunk(fallback);
    return fallback;
  }
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let full = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    for (const ln of dec.decode(value).split("\n").filter(l => l.startsWith("data:"))) {
      try {
        const j = JSON.parse(ln.slice(5));
        if (j.type === "content_block_delta" && j.delta?.text) {
          full += j.delta.text;
          onChunk(full);
        }
      } catch {}
    }
  }
  return full;
}

// Multi-agent call — routes to /api/agent which selects model per agentType
// Handles both OpenAI SSE format (OCZ/OpenRouter) and Anthropic SSE format (fallback)
async function callAgent(agentType, messages, onChunk, { system } = {}) {
  const msgs = system ? [{ role:"system", content:system }, ...messages] : messages;
  const res = await fetch("/api/agent", {
    method:"POST",
    headers:{ "Content-Type":"application/json" },
    body:JSON.stringify({ agentType, messages:msgs, stream:true }),
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
        // OpenAI / OpenRouter format
        const t1 = j.choices?.[0]?.delta?.content ?? "";
        // Anthropic SSE format (fallback path)
        const t2 = (j.type === "content_block_delta" && j.delta?.text) ? j.delta.text : "";
        const chunk = t1 || t2;
        if (chunk) { full += chunk; onChunk(full); }
      } catch {}
    }
  }
  if (!full) {
    const errMsg = `[Agent ${agentType} returned empty response — all models may be unavailable or timed out. Check backend logs and verify API key at https://opencode.ai/zen/]`;
    onChunk(errMsg);
    return errMsg;
  }
  return full;
}

// ─── MARKDOWN RENDERER ────────────────────────────────────────────────────────
function MD({text,color="#38bdf8"}){
  return<div style={{fontFamily:"'IBM Plex Mono',monospace",fontSize:"0.74rem",lineHeight:1.75,color:"#cbd5e1"}}>
    {text.split("\n").map((line,i)=>{
      if(/^### /.test(line))return<div key={i} style={{color,fontWeight:700,fontSize:"0.79rem",marginTop:14,marginBottom:5,borderBottom:`1px solid ${color}33`,paddingBottom:3,fontFamily:"'Oxanium',monospace"}}>{line.replace(/^### /,"")}</div>;
      if(/^---$/.test(line.trim()))return<hr key={i} style={{border:"none",borderTop:"1px solid #1e293b",margin:"10px 0"}}/>;
      if(/^\*\*🤖/.test(line))return<div key={i} style={{color:"#a78bfa",fontWeight:700,marginTop:6}}>{line.replace(/\*\*/g,"")}</div>;
      if(/^> `/.test(line)){const cmd=line.match(/`([^`]+)`/)?.[1];const rest=line.replace(/^> `[^`]+`\s*—?\s*/,"");return<div key={i} style={{display:"flex",gap:7,margin:"3px 0",alignItems:"flex-start"}}><code style={{background:"#0f2a3a",border:"1px solid #164e63",color:"#22d3ee",padding:"2px 8px",borderRadius:4,whiteSpace:"nowrap",fontSize:"0.69rem"}}>{cmd}</code><span style={{color:"#475569",fontSize:"0.69rem",paddingTop:2}}>{rest}</span></div>;}
      if(/^> /.test(line))return<div key={i} style={{color:"#475569",paddingLeft:10,borderLeft:"2px solid #1e293b",margin:"2px 0"}}>{line.slice(2)}</div>;
      if(/^[-•] /.test(line))return<div key={i} style={{paddingLeft:12,color:"#94a3b8"}}>• {line.slice(2)}</div>;
      if(line.trim()==="")return<div key={i} style={{height:4}}/>;
      return<div key={i}>{line.split(/(`[^`]+`|\*\*[^*]+\*\*)/).map((s,j)=>{if(/^`/.test(s))return<code key={j} style={{background:"#0f2d3d",color:"#67e8f9",padding:"1px 5px",borderRadius:3}}>{s.slice(1,-1)}</code>;if(/^\*\*/.test(s))return<strong key={j} style={{color:"#f1f5f9"}}>{s.slice(2,-2)}</strong>;return s;})}</div>;
    })}
  </div>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SLACK ALERTS HUB
// ═══════════════════════════════════════════════════════════════════════════════
function normalizeApiAlert(a){return{...a,irId:a.irId||null,agentReport:null,reportLoading:false,reportPhase:null,isTest:false,iocs:Array.isArray(a.iocs)?a.iocs:[]}; }

function timeAgo(iso){const s=Math.floor((Date.now()-new Date(iso))/1000);if(s<60)return`${s}s ago`;if(s<3600)return`${Math.floor(s/60)}m ago`;return`${Math.floor(s/3600)}h ago`;}

// ─── INLINE AGENT CHAT — embedded investigation panel ─────────────────────────
// Self-contained streaming chat that runs inside any card/row. Auto-triggers
// investigation on mount using all real Wazuh observables when liveAlert is given.
function InlineAgentChat({rule,liveAlert,customRules,gc}){
  const[msgs,setMsgs]=useState([]);
  const[inp,setInp]=useState("");
  const[loading,setLoading]=useState(false);
  const[streaming,setStreaming]=useState("");
  const btm=useRef(null);
  const started=useRef(false);
  const color=gc||"#a855f7";

  const cb=(customRules||[]).length?`\nCUSTOM RULES IN SCOPE:\n${customRules.map(r=>`- [${r.id}] ${r.name} | ${r.tactic} | ${r.mitre}${r.level?` | level:${r.level}`:""}`).join("\n")}`:"";

  const SYS=liveAlert
    ?`You are an autonomous SOC incident responder analyzing a LIVE Wazuh detection. Stack: Wazuh SIEM | Suricata | Zeek | YARA | Honeypots | IR playbooks: triage_collect.yml/containment_block_src.yml/ir_suricata_alert.yml/close_case.yml${cb}

LIVE DETECTION:
  Alert ID: ${liveAlert.id}
  Rule: ${liveAlert.ruleName} (${liveAlert.ruleId}) — Level ${liveAlert.level||"?"} [${liveAlert.severity}]
  Time: ${liveAlert.time}
  Tactic: ${liveAlert.tactic} | MITRE: ${liveAlert.mitre}
  Groups: ${(liveAlert.groups||[]).join(",")||"—"}
  Decoder: ${liveAlert.decoder||"—"} | Location: ${liveAlert.location||"—"}

ENDPOINT:
  Host: ${liveAlert.host}
  Agent: ${liveAlert.agentId||"—"}@${liveAlert.agentIp||"—"}
  Account: ${liveAlert.account}

NETWORK:
  src_ip: ${liveAlert.srcIp}
  dst_ip: ${liveAlert.dstIp}

IOCs:
${(liveAlert.iocs||[]).map(i=>`  [${i.t}] ${i.v}`).join("\n")||"  none extracted"}

RAW LOG: ${liveAlert.fullLog||"(not available)"}

Produce a full investigation:
### 🔍 TRIAGE
### ⏱️ TIMELINE
### 🧠 ATTACK VECTOR
### 🔗 CORRELATION
### 🛑 CONTAINMENT
### 📋 LOG PULL COMMANDS
### 🔎 HUNT QUERIES
### 📊 CASE REPORT`
    :`You are an autonomous SOC agent investigating detection rule: ${rule?.id} — ${rule?.name}. Severity: ${rule?.severity} | Tactic: ${rule?.tactic} | MITRE: ${rule?.mitre}${rule?.wazuhRuleId?` | Wazuh rule ${rule?.wazuhRuleId} level ${rule?.level}`:""}${cb}
Produce: ### 🔍 TRIAGE / ### 🧠 ATTACK VECTOR / ### 🛑 CONTAINMENT / ### 📋 LOG PULL COMMANDS / ### 📊 CASE REPORT`;

  const initMsg=liveAlert
    ?`LIVE ALERT — FULL INVESTIGATION:\n${formatAlertForAgent(liveAlert)}\n\nBegin investigation using all real observables above.`
    :`RULE INVESTIGATION: ${rule?.id} — ${rule?.name}\n${rule?.severity} | ${rule?.tactic} | ${rule?.mitre}\nBegin investigation.`;

  useEffect(()=>{if(started.current)return;started.current=true;send(initMsg);},[]);
  useEffect(()=>{btm.current?.scrollIntoView({behavior:"smooth"});},[msgs,streaming]);

  async function send(msg){
    setLoading(true);setStreaming("");
    const next=[...msgs,{role:"user",content:msg}];setMsgs(next);
    let full="";
    await callAgent("investigate",next,c=>{full=c;setStreaming(c);},{system:SYS});
    setStreaming("");setMsgs([...next,{role:"assistant",content:full}]);setLoading(false);
  }

  return(
    <div style={{borderTop:`1px solid ${color}22`,marginTop:10,paddingTop:10}}>
      <div style={{maxHeight:420,overflowY:"auto",display:"flex",flexDirection:"column",gap:8,marginBottom:8,paddingRight:4}}>
        {msgs.map((m,i)=>(
          <div key={i}>
            {m.role==="user"&&i>0&&<div style={{textAlign:"right",marginBottom:4}}><span style={{background:"#0f2a3a",border:`1px solid ${color}33`,borderRadius:"8px 8px 2px 8px",padding:"4px 10px",color:"#cbd5e1",fontSize:"0.68rem",fontFamily:"monospace",display:"inline-block",maxWidth:"72%"}}>{m.content}</span></div>}
            {m.role==="assistant"&&<div style={{background:"#060d1a",border:`1px solid ${color}22`,borderRadius:"2px 8px 8px 8px",padding:"10px 12px"}}><div style={{color,fontSize:"0.59rem",fontFamily:"monospace",marginBottom:5,letterSpacing:1}}>⚡ OPXDR AGENT · {ts()}</div><MD text={m.content} color={color}/></div>}
          </div>
        ))}
        {loading&&!streaming&&<div style={{background:"#060d1a",border:`1px solid ${color}33`,borderRadius:"2px 8px 8px 8px",padding:"10px 12px"}}><div style={{color,fontSize:"0.59rem",fontFamily:"monospace",marginBottom:5,letterSpacing:1,animation:"pulse 1.5s infinite"}}>⚡ ANALYZING... (model warming up — may take 1-2 min)</div></div>}
        {streaming&&<div style={{background:"#060d1a",border:`1px solid ${color}33`,borderRadius:"2px 8px 8px 8px",padding:"10px 12px"}}><div style={{color,fontSize:"0.59rem",fontFamily:"monospace",marginBottom:5,letterSpacing:1,animation:"pulse 1.5s infinite"}}>⚡ ANALYZING...</div><MD text={streaming} color={color}/><span style={{color,animation:"blink 1s infinite"}}>▋</span></div>}
        <div ref={btm}/>
      </div>
      <div style={{display:"flex",gap:6}}>
        <input value={inp} onChange={e=>setInp(e.target.value)} onKeyDown={e=>e.key==="Enter"&&!loading&&inp.trim()&&(send(inp.trim()),setInp(""))} placeholder="follow-up: pull logs / hunt iocs / expand ioc / block ip / correlate / deploy ir..." disabled={loading} style={{flex:1,background:"#0a1628",border:`1px solid ${color}44`,borderRadius:6,color:"#e2e8f0",padding:"6px 10px",fontSize:"0.69rem",fontFamily:"'IBM Plex Mono',monospace",outline:"none"}} onFocus={e=>e.target.style.borderColor=color} onBlur={e=>e.target.style.borderColor=color+"44"}/>
        <button onClick={()=>{if(inp.trim()&&!loading){send(inp.trim());setInp("");}}} disabled={loading||!inp.trim()} style={{background:loading?"#1e293b":color,color:"#020817",border:"none",borderRadius:6,padding:"6px 14px",fontWeight:700,fontSize:"0.7rem",cursor:loading?"not-allowed":"pointer",fontFamily:"monospace",whiteSpace:"nowrap"}}>{loading?"...":"SEND ↵"}</button>
      </div>
    </div>
  );
}

function SlackAlertCard({alert,onRunAgent,onOpenFull,onInvestigate,customRules,onSaveDoc,settings}){
  const s=SEV[alert.severity]||SEV.HIGH;
  const [invLoading,setInvLoading]=useState(false);
  const [invText,setInvText]=useState("");
  const [invDone,setInvDone]=useState(false);
  const [invInput,setInvInput]=useState("");
  const [invFollowUpLoading,setInvFollowUpLoading]=useState(false);
  const [invFollowUpText,setInvFollowUpText]=useState("");
  const invAutoRan=useRef(false);
  const gc="#38bdf8";
  const QUICK=alert.severity==="CRITICAL"||alert.severity==="HIGH"
    ?["pull logs","hunt iocs","expand ioc","block ip","correlate","deploy ir","export alert","close case"]
    :["pull logs","anomaly hunt","attack chain","run containment","correlate","export alert","close case"];

  useEffect(()=>{
    if(invAutoRan.current)return;
    if(!settings?.autoAi)return;
    const sevOk=settings.autoMinSev==="CRITICAL"
      ?alert.severity==="CRITICAL"
      :(alert.severity==="CRITICAL"||alert.severity==="HIGH");
    if(!sevOk)return;
    invAutoRan.current=true;
    runInvestigation();
  },[]);

  async function runInvestigation(){
    setInvLoading(true);
    setInvText("");
    setInvDone(false);
    const msg=`Investigate this security alert in full detail. Produce a comprehensive executive investigation report.\n\n${formatAlertForAgent(alert)}`;
    const sys=`You are a senior SOC investigator. Analyze this alert and produce a comprehensive executive investigation report using EXACTLY this format:

🔍 [ALERT ID] — Full Investigation Report
---

### 1. Alert Summary
| Field | Value |
|---|---|
| Alert ID | ... |
| Title | ... |
| Severity | ... |
| MITRE Tactic | ... |
| Rule ID | ... |
| Status | INVESTIGATED |
| Host | ... |
| Source IP | ... |
| Decoder | ... |
| Log Source | ... |

### 2. Timeline of Events
Chronologically ordered phases with source attribution. Use tables with Timestamp | Event | Status columns. Group into phases (🔴 Phase N — Title).

### 3. Indicators of Compromise (IOCs)
Split into Network IOCs and Host-Based IOCs tables. Include IPs, URLs, User-Agents, file paths, exploit methods.

### 4. Kill Chain Mapping
MITRE ATT&CK stages mapped to observed activity. Table with Stage | Technique | Observed.

### 5. Risk Assessment
Table with Factor | Assessment. Cover: exploitability, OGNL/expression eval success, service status, internal pivot risk, C2 communication, current sessions.

### 6. Recommended Actions
- ✅ Immediate (completed actions)
- 🔴 Urgent (must-do now)
- 🟡 Follow-up (should-do)

### 7. Conclusion
Confidence level (HIGH/MEDIUM/LOW), summary narrative of the attack with key findings.

Be specific — use exact IPs, hostnames, timestamps, URLs, and commands from the alert data.`;
    try{
      await callAgent("investigate",[{role:"user",content:msg}],(full)=>{setInvText(full);},{system:sys});
      setInvDone(true);
    }catch(e){
      setInvText(`[Investigation failed: ${e.message}]`);
    }finally{
      setInvLoading(false);
    }
  }

  async function runFollowUp(text){
    if(!text.trim()||invFollowUpLoading)return;
    setInvFollowUpLoading(true);
    setInvFollowUpText("");
    const msgs=[{role:"user",content:text}];
    try{
      await callAgent("investigate",msgs,(full)=>{setInvFollowUpText(full);},{system:"You are a senior SOC investigator executing follow-up tasks on the alert."});
    }catch(e){
      setInvFollowUpText(`[Follow-up failed: ${e.message}]`);
    }finally{
      setInvFollowUpLoading(false);
    }
  }

  return(
    <div style={{background:"#0a1117",border:`1px solid ${s.border+"33"}`,borderRadius:10,overflow:"hidden",marginBottom:10}}>
      {/* Slack-style left accent */}
      <div style={{display:"flex"}}>
        <div style={{width:4,background:s.border,flexShrink:0}}/>
        <div style={{flex:1,padding:"12px 14px"}}>
          {/* Header */}
          <div style={{display:"flex",alignItems:"flex-start",justifyContent:"space-between",marginBottom:8}}>
            <div>
              <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
                <span style={{color:"#e2e8f0",fontFamily:"'Oxanium',monospace",fontWeight:700,fontSize:"0.84rem"}}>🚨 {alert.ruleName}</span>
                <SB l={alert.severity}/>
                {alert.injected&&<span style={{background:"#38bdf820",border:"1px solid #38bdf855",color:"#38bdf8",padding:"1px 7px",borderRadius:3,fontSize:"0.62rem",fontFamily:"monospace",letterSpacing:1}}>INJECTED</span>}
              </div>
              <div style={{display:"flex",gap:6,alignItems:"center",flexWrap:"wrap"}}>
                <code style={{color:"#334155",fontSize:"0.65rem",fontFamily:"monospace"}}>{alert.id}</code>
                <TB t={alert.tactic}/>
                {alert.mitre.split(",").map(m=><code key={m} style={{background:"#0f172a",border:"1px solid #1e293b",color:"#79c0ff",padding:"1px 6px",borderRadius:3,fontSize:"0.64rem",fontFamily:"monospace"}}>{m}</code>)}
              </div>
            </div>
            <span style={{color:"#334155",fontSize:"0.68rem",fontFamily:"monospace",whiteSpace:"nowrap",marginLeft:8}}>{timeAgo(alert.time)}</span>
          </div>

          {/* Field grid: host/agent + network fields */}
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(155px,1fr))",gap:5,marginBottom:8}}>
            {[
              {k:"host",v:alert.host},
              {k:"agent_id",v:alert.agentId&&alert.agentId!=="—"?`${alert.agentId} @ ${alert.agentIp||""}`:null},
              {k:"src_ip",v:alert.srcIp},
              {k:"dst_ip",v:alert.dstIp},
              {k:"account",v:alert.account},
              {k:"location",v:alert.location},
            ].filter(({v})=>v&&v!=="—"&&v!=="— @ ")
              .map(({k,v})=>(
                <div key={k} style={{background:"#060d1a",border:"1px solid #1e293b",borderRadius:5,padding:"4px 8px"}}>
                  <div style={{color:"#475569",fontSize:"0.6rem",fontFamily:"monospace",letterSpacing:"0.05em"}}>{k}</div>
                  <div style={{color:"#e2e8f0",fontSize:"0.72rem",fontFamily:"monospace",wordBreak:"break-all"}}>{v}</div>
                </div>
              ))}
          </div>

          {/* IOC tags */}
          {alert.iocs&&alert.iocs.length>0&&(
            <div style={{display:"flex",gap:5,flexWrap:"wrap",marginBottom:8,padding:"6px 8px",background:"#0d0208",border:"1px solid #fbbf2422",borderRadius:6}}>
              <span style={{color:"#475569",fontSize:"0.6rem",fontFamily:"monospace",alignSelf:"center",marginRight:2}}>IOC</span>
              {alert.iocs.map((ioc,i)=>(
                <span key={i} style={{background:"#fbbf2412",border:"1px solid #fbbf2450",color:"#fcd34d",padding:"2px 9px",borderRadius:4,fontSize:"0.67rem",fontFamily:"monospace",letterSpacing:"0.02em"}}>
                  [{ioc.t}] {ioc.v}
                </span>
              ))}
            </div>
          )}

          {/* Raw Wazuh log line */}
          {alert.fullLog&&(
            <div style={{marginBottom:8,padding:"4px 8px",background:"#060d1a",border:"1px solid #1e293b33",borderRadius:5}}>
              <div style={{color:"#475569",fontSize:"0.6rem",fontFamily:"monospace",marginBottom:2}}>raw_log</div>
              <div style={{color:"#64748b",fontSize:"0.65rem",fontFamily:"monospace",wordBreak:"break-all",whiteSpace:"pre-wrap"}}>{alert.fullLog.slice(0,200)}{alert.fullLog.length>200?"…":""}</div>
            </div>
          )}

          {/* IR badge if deployed */}
          {alert.irId&&<div style={{display:"inline-flex",alignItems:"center",gap:6,background:"#22c55e15",border:"1px solid #22c55e33",borderRadius:5,padding:"3px 10px",marginBottom:10}}>
            <span style={{color:"#22c55e",fontSize:"0.67rem",fontFamily:"monospace"}}>🚨 IR DEPLOYED: {alert.irId}</span>
          </div>}

          {/* Actions */}
          {!invLoading&&!invDone&&(
            <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
              <button onClick={()=>runInvestigation()} style={{background:"#22c55e20",border:"1px solid #22c55e55",color:"#22c55e",borderRadius:6,padding:"5px 13px",fontSize:"0.71rem",fontWeight:700,cursor:"pointer",fontFamily:"monospace"}}>
                🔍 Run Investigation
              </button>
              <button onClick={()=>onRunAgent(alert)} style={{background:"#38bdf820",border:"1px solid #38bdf855",color:"#38bdf8",borderRadius:6,padding:"5px 13px",fontSize:"0.71rem",fontWeight:700,cursor:"pointer",fontFamily:"monospace"}}>
                {alert.reportLoading
                  ? alert.reportPhase==="log-analysis" ? "⟳ Phase 1: Log Analysis..."
                  : alert.reportPhase==="report"        ? "⟳ Phase 2: Report Agent..."
                  : "⟳ Analyzing..."
                  : "⚡ Run Agent Report"}
              </button>
              <button onClick={()=>onInvestigate&&onInvestigate(alert)} style={{background:"#a855f720",border:"1px solid #a855f755",color:"#a855f7",borderRadius:6,padding:"5px 13px",fontSize:"0.71rem",fontWeight:700,cursor:"pointer",fontFamily:"monospace"}}>
                🔬 Full Investigation
              </button>
            </div>
          )}

          {/* Streaming investigation report */}
          {(invLoading||invText)&&(
            <div style={{marginTop:12,background:"#060d1a",border:`1px solid ${invDone?"#22c55e44":"#38bdf833"}`,borderRadius:8,padding:"12px 14px"}}>
              <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:8}}>
                <div style={{color:invDone?"#22c55e":"#38bdf8",fontSize:"0.65rem",fontFamily:"monospace"}}>
                  {invLoading ? "⚡ EXECUTIVE INVESTIGATION REPORT · ANALYZING..." : "✓ EXECUTIVE INVESTIGATION REPORT"}
                </div>
                {invDone&&onSaveDoc&&<button onClick={()=>onSaveDoc({type:"investigation",title:`Investigation: ${alert.ruleName}`,alert,report:invText})} style={{background:"#22c55e20",border:"1px solid #22c55e55",color:"#22c55e",borderRadius:5,padding:"3px 10px",fontSize:"0.64rem",fontWeight:700,cursor:"pointer",fontFamily:"monospace"}}>💾 Save</button>}
              </div>
              <MD text={invText+(invLoading?"\n\n`⚡ generating...`":"")} color="#38bdf8"/>
            </div>
          )}

          {/* Post-completion toolbar — Save / Further Triage / Recommend IR / Save & Exit */}
          {invDone&&(
            <div style={{marginTop:12,padding:"6px 0",borderTop:"1px solid #22c55e33"}}>
              <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap",marginBottom:8}}>
                <span style={{color:"#22c55e",fontSize:"0.63rem",fontFamily:"monospace",letterSpacing:1,display:"flex",alignItems:"center",gap:5}}>
                  <span style={{color:"#22c55e",animation:"blink 2s step-end infinite"}}>✓</span> ANALYSIS COMPLETE — choose next action or continue chatting
                </span>
                <div style={{flex:1}}/>
                {onSaveDoc&&<button onClick={()=>onSaveDoc({type:"investigation",title:`Investigation: ${alert.ruleName}`,alert,report:invText})} style={{background:"#22c55e20",border:"1px solid #22c55e55",color:"#22c55e",borderRadius:5,padding:"5px 13px",fontSize:"0.67rem",fontWeight:700,cursor:"pointer",fontFamily:"monospace"}}>💾 Save</button>}
                <button onClick={()=>{runFollowUp("Based on the investigation above, provide: (1) Top 3 immediate threat hunting queries using Wazuh/KQL/Sigma targeting this specific host, source IP, and rule groups; (2) IOC pivot and expansion steps for each confirmed IOC; (3) Anomaly detection queries for the agent; (4) Recommended next triage actions in priority order.")}} style={{background:"#38bdf820",border:"1px solid #38bdf855",color:"#38bdf8",borderRadius:5,padding:"5px 13px",fontSize:"0.67rem",fontWeight:700,cursor:"pointer",fontFamily:"monospace"}}>🔍 Further Triage</button>
                <button onClick={()=>{runFollowUp("Generate a full Incident Response plan for this detection. Provide: ### 🚨 IR CLASSIFICATION — severity, IR case priority, and notification matrix; ### 📋 CONTAINMENT STEPS — exact shell/Ansible commands to block/isolate NOW; ### 🔍 EVIDENCE COLLECTION — forensic commands for memory, disk, network artifacts; ### 🧹 ERADICATION — how to fully remove the threat; ### 🔄 RECOVERY — steps to safely restore; ### 📝 IR PLAYBOOK REFERENCE — which playbook template to use and how to instantiate it. Be specific with commands, hostnames, and IPs from the alert.")}} style={{background:"#f9731620",border:"1px solid #f9731655",color:"#f97316",borderRadius:5,padding:"5px 13px",fontSize:"0.67rem",fontWeight:700,cursor:"pointer",fontFamily:"monospace"}}>🚨 Recommend IR</button>
                {onSaveDoc&&<button onClick={()=>{onSaveDoc({type:"investigation",title:`Investigation: ${alert.ruleName}`,alert,report:invText});setInvDone(false);setInvText("");setInvInput("");setInvFollowUpText("");}} style={{background:"#1e293b",border:"1px solid #334155",color:"#64748b",borderRadius:5,padding:"5px 13px",fontSize:"0.67rem",fontWeight:700,cursor:"pointer",fontFamily:"monospace"}}>💾 Save & Exit</button>}
              </div>
              {/* Quick preset buttons */}
              <div style={{display:"flex",gap:5,flexWrap:"wrap",marginBottom:8}}>
                {QUICK.map(t=><button key={t} onClick={()=>setInvInput(t)} style={{background:"#0f172a",border:"1px solid #1e293b",color:"#64748b",borderRadius:5,padding:"3px 9px",fontSize:"0.67rem",cursor:"pointer",fontFamily:"monospace"}} onMouseEnter={e=>{e.target.style.borderColor=gc;e.target.style.color=gc;}} onMouseLeave={e=>{e.target.style.borderColor="#1e293b";e.target.style.color="#64748b";}}>{t}</button>)}
              </div>
              {/* Follow-up input */}
              <div style={{display:"flex",gap:7}}>
                <input value={invInput} onChange={e=>setInvInput(e.target.value)} onKeyDown={e=>e.key==="Enter"&&!invFollowUpLoading&&invInput.trim()&&(runFollowUp(invInput.trim()),setInvInput(""))} placeholder="follow-up: pull logs / hunt iocs / block ip..." disabled={invFollowUpLoading} style={{flex:1,background:"#0a1628",border:"1px solid #1e293b",borderRadius:7,color:"#e2e8f0",padding:"6px 10px",fontSize:"0.7rem",fontFamily:"'IBM Plex Mono',monospace",outline:"none"}} onFocus={e=>e.target.style.borderColor=gc} onBlur={e=>e.target.style.borderColor="#1e293b"}/>
                <button onClick={()=>{if(invInput.trim()&&!invFollowUpLoading){runFollowUp(invInput.trim());setInvInput("");}}} disabled={invFollowUpLoading||!invInput.trim()} style={{background:invFollowUpLoading?"#1e293b":gc,color:invFollowUpLoading?"#475569":"#020817",border:"none",borderRadius:7,padding:"6px 12px",fontWeight:700,fontSize:"0.7rem",cursor:invFollowUpLoading?"not-allowed":"pointer",fontFamily:"monospace"}}>{invFollowUpLoading?"...":"SEND"}</button>
              </div>
              {/* Follow-up streaming response */}
              {invFollowUpText&&(
                <div style={{marginTop:8,background:"#0a1628",border:"1px solid #1e293b",borderRadius:6,padding:"8px 10px"}}>
                  <MD text={invFollowUpText+(invFollowUpLoading?"\n\n`⚡ generating...`":"")} color="#94a3b8"/>
                </div>
              )}
            </div>
          )}

          {/* Agent report inline (existing) */}
          {alert.agentReport&&(
            <div style={{marginTop:12,background:"#060d1a",border:"1px solid #38bdf833",borderRadius:8,padding:"12px 14px"}}>
              <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:8}}>
                <div style={{color:"#38bdf8",fontSize:"0.65rem",fontFamily:"monospace"}}>⚡ AGENT REPORT · {alert.agentReport.at}</div>
                {onSaveDoc&&<button onClick={()=>onSaveDoc({type:"report",title:`Report: ${alert.ruleName}`,alert,report:alert.agentReport.text})} style={{background:"#22c55e20",border:"1px solid #22c55e55",color:"#22c55e",borderRadius:5,padding:"3px 10px",fontSize:"0.64rem",fontWeight:700,cursor:"pointer",fontFamily:"monospace"}}>💾 Save Report</button>}
              </div>
              <MD text={alert.agentReport.text} color="#38bdf8"/>
            </div>
          )}

        </div>
      </div>
    </div>
  );
}

// Shared system prompt + alert formatter — used by SlackHub manual run AND
// the App-level auto-analyzer triggered on SSE arrival.
const SLACK_AGENT_SYS=(alert)=>`You are a SOC agent. An alert just fired on the Wazuh SIEM. Produce a structured investigation report using EXACTLY this format:

🔍 [ALERT ID] — Full Investigation Report
---

### 1. Alert Summary
| Field | Value |
|---|---|
| Alert ID | ${alert.id} |
| Title | ${alert.ruleName} |
| Severity | ${alert.severity} |
| MITRE Tactic | ${alert.tactic} (${alert.mitre}) |
| Rule ID | ${alert.ruleId} |
| Status | INVESTIGATED |
| Host | ${alert.host} |
| Source IP | ${alert.srcIp} |
| Decoder | ${alert.decoder||"—"} |
| Log Source | ${alert.location||"—"} |

### 2. Timeline of Events
Chronological phases. Tables with Timestamp | Event | Status columns. Group into phases.

### 3. Indicators of Compromise (IOCs)
Network IOCs table (IPs, URLs, User-Agents) + Host-Based IOCs table (paths, methods). Tag each: CONFIRMED/SUSPECTED/NOISE.

### 4. Kill Chain Mapping
MITRE ATT&CK stage | Technique | Observed activity.

### 5. Risk Assessment
Exploitability, service status, internal pivot risk, C2 comms, current sessions.

### 6. Recommended Actions
✅ Immediate completed actions, 🔴 Urgent actions with specific commands/IPs, 🟡 Follow-up.

### 7. Conclusion
Confidence level and summary narrative.

${alert.irId?`IR case ${alert.irId} IS deployed. State what it covers and gaps.`:"No IR playbook deployed yet."}

End with: ---\n**🤖 Reply with:** \`deploy IR\` \`pull logs\` \`block ip\` \`correlate\` or describe action.`;

const formatAlertForAgent=(alert)=>{
  const iocStr=(alert.iocs||[]).map(i=>`[${i.t}] ${i.v}`).join(", ")||"none extracted";
  const lines=[
    `ALERT FIRED:`,
    `ID: ${alert.id}`,
    `Rule: ${alert.ruleName} (${alert.ruleId})`,
    `Severity: ${alert.severity} (level ${alert.level||"?"})`,
    `Tactic: ${alert.tactic} | MITRE: ${alert.mitre}`,
    ``,
    `ENDPOINT:`,
    `  Host:    ${alert.host}`,
    `  Agent:   ${alert.agentId||"—"} @ ${alert.agentIp||"—"}`,
    `  Account: ${alert.account}`,
    ``,
    `NETWORK:`,
    `  src_ip:  ${alert.srcIp}`,
    `  dst_ip:  ${alert.dstIp}`,
    ``,
    `IOCs: ${iocStr}`,
    ``,
    `DETECTION:`,
    `  Decoder:  ${alert.decoder||"—"}`,
    `  Location: ${alert.location||"—"}`,
  ];
  if(alert.fullLog)lines.push(`  Raw log: ${alert.fullLog}`);
  if(alert.irId)lines.push(``,`IR Deployed: ${alert.irId}`);
  return lines.join("\n");
};

// Generate agent report + (optionally) push to Slack via backend webhook.
async function generateAgentReport(alert,{slackNotify=false}={}){
  const report=await callAgent("slackReport",[{role:"user",content:formatAlertForAgent(alert)}],()=>{},{system:SLACK_AGENT_SYS(alert)});
  if(slackNotify){
    try{
      await fetch("/api/slack/notify",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({alert,report}),
      });
    }catch(e){console.warn("Slack notify failed:",e);}
  }
  return report;
}

function SlackHub({alerts,setAlerts,onOpenFull,onInvestigate,settings,setSettings,customRules,onSaveDoc}){
  const critCount=alerts.filter(a=>a.severity==="CRITICAL").length;
  const highCount=alerts.filter(a=>a.severity==="HIGH").length;
  const medCount=alerts.filter(a=>a.severity==="MEDIUM").length;
  const withIR=alerts.filter(a=>a.irId).length;

  async function runAgentReport(alert){
    // Phase 1 — Log Analysis (Llama 3.1 8B): normalize IOCs, classify event
    setAlerts(prev=>prev.map(a=>a.id===alert.id?{...a,reportLoading:true,reportPhase:"log-analysis"}:a));
    let logCtx="";
    try{
      logCtx=await callAgent("logAnalysis",[{role:"user",content:`Analyze and normalize this security alert:\n${formatAlertForAgent(alert)}\n\nTasks:\n1. Classify each IOC: CONFIRMED/SUSPECTED/NOISE\n2. Classify event: BENIGN/SUSPICIOUS/MALICIOUS\n3. Identify MITRE phase and attack pattern\n4. Output a 3-sentence structured summary for the report agent.`}],()=>{},{system:"You are a SOC log analysis pre-processor (Llama 3.1 8B). Parse alert metadata, normalize IOC fields, classify each IOC and the overall event. Produce a concise 3-sentence summary: (1) event classification and confidence, (2) IOC classification, (3) recommended analyst action."});
    }catch(e){console.warn("[logAnalysis phase]",e.message);}
    // Phase 2 — Slack Report (Llama 3.1 70B): full structured report
    setAlerts(prev=>prev.map(a=>a.id===alert.id?{...a,reportPhase:"report"}:a));
    const enriched=logCtx?`LOG ANALYSIS PRE-PROCESSOR (Llama 8B):\n${logCtx}\n\n---\n${formatAlertForAgent(alert)}`:formatAlertForAgent(alert);
    const report=await callAgent("slackReport",[{role:"user",content:enriched}],()=>{},{system:SLACK_AGENT_SYS(alert)});
    setAlerts(prev=>prev.map(a=>a.id===alert.id?{...a,reportLoading:false,reportPhase:null,agentReport:{text:report,logCtx,at:ts()}}:a));
    if(settings.slackNotify&&settings.slackEnabled){
      try{await fetch("/api/slack/notify",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({alert,report})});}catch{}
    }
  }

  const Toggle=({on,onClick,label,disabled,disabledReason})=>(
    <button onClick={disabled?undefined:onClick} title={disabled?disabledReason:""} style={{
      background:on?"#22c55e22":"#0a1628",border:`1px solid ${on?"#22c55e55":"#1e293b"}`,
      color:on?"#22c55e":"#475569",borderRadius:6,padding:"4px 10px",fontSize:"0.66rem",
      fontFamily:"monospace",cursor:disabled?"not-allowed":"pointer",fontWeight:on?700:400,
      letterSpacing:1,opacity:disabled?0.5:1,
    }}>{on?"●":"○"} {label}</button>
  );

  return(
    <div style={{padding:"16px 24px"}}>
      {/* Stats bar */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:16}}>
        {[
          {label:"TOTAL ALERTS",val:alerts.length,  color:"#e2e8f0"},
          {label:"MEDIUM",      val:medCount,       color:"#fbbf24"},
          {label:"HIGH",        val:highCount,      color:"#f97316"},
          {label:"CRITICAL",    val:critCount,      color:"#ff6060"},
        ].map(({label,val,color})=>(
          <div key={label} style={{background:"#060d1a",border:"1px solid #1e293b",borderRadius:8,padding:"10px 14px"}}>
            <div style={{color:"#334155",fontSize:"0.62rem",fontFamily:"monospace",letterSpacing:1}}>{label}</div>
            <div style={{color,fontSize:"1.4rem",fontFamily:"'Oxanium',monospace",fontWeight:800,marginTop:3}}>{val}</div>
          </div>
        ))}
      </div>

      {/* AI / Slack control bar */}
      <div style={{display:"flex",alignItems:"center",gap:8,flexWrap:"wrap",background:"#060d1a",border:"1px solid #1e293b",borderRadius:8,padding:"8px 12px",marginBottom:12}}>
        <span style={{color:"#475569",fontSize:"0.64rem",fontFamily:"monospace",letterSpacing:1,marginRight:4}}>AGENT CONTROLS</span>
        <Toggle on={settings.autoAi} onClick={()=>setSettings(s=>({...s,autoAi:!s.autoAi}))}
          label="AI AUTO-REPORT" disabled={!settings.aiProvider||settings.aiProvider==="none"}
          disabledReason="No AI key configured (.env: OPENCODE_API_KEY or ANTHROPIC_API_KEY)"/>
        <Toggle on={settings.slackNotify} onClick={()=>setSettings(s=>({...s,slackNotify:!s.slackNotify}))}
          label="SLACK NOTIFY" disabled={!settings.slackEnabled}
          disabledReason="No SLACK_WEBHOOK_URL configured in .env"/>
        <span style={{color:"#475569",fontSize:"0.64rem",fontFamily:"monospace"}}>•</span>
        <span style={{color:"#475569",fontSize:"0.64rem",fontFamily:"monospace"}}>min severity</span>
        <select value={settings.autoMinSev} onChange={e=>setSettings(s=>({...s,autoMinSev:e.target.value}))}
          style={{background:"#0a1628",border:"1px solid #1e293b",color:"#cbd5e1",borderRadius:5,padding:"3px 7px",fontSize:"0.66rem",fontFamily:"monospace"}}>
          <option value="HIGH">HIGH+</option>
          <option value="CRITICAL">CRITICAL only</option>
        </select>
        <div style={{flex:1}}/>
        <span style={{color:settings.aiProvider==="none"?"#ef4444":"#22c55e",fontSize:"0.62rem",fontFamily:"monospace"}}>
          AI: {settings.aiProvider||"…"}
        </span>
        <span style={{color:settings.slackEnabled?"#22c55e":"#475569",fontSize:"0.62rem",fontFamily:"monospace"}}>
          SLACK: {settings.slackEnabled?settings.slackChannel||"on":"off"}
        </span>
      </div>

      {/* Alert feed */}
      <div style={{marginBottom:8,display:"flex",alignItems:"center",justifyContent:"space-between"}}>
        <span style={{color:"#334155",fontSize:"0.67rem",fontFamily:"monospace",letterSpacing:1}}>LIVE ALERT FEED — {settings.slackChannel||"#soc-alerts"}</span>
        <span style={{background:"#f9731620",border:"1px solid #f9731644",color:"#f97316",padding:"1px 8px",borderRadius:3,fontSize:"0.61rem",fontFamily:"monospace",letterSpacing:1}}>HIGH+ ONLY</span>
        <span style={{color:"#22c55e",fontSize:"0.65rem",fontFamily:"monospace",animation:"pulse 2s infinite"}}>● CONNECTED</span>
      </div>
      {alerts.map(a=><SlackAlertCard key={a.id} alert={a} onRunAgent={runAgentReport} onOpenFull={onOpenFull} onInvestigate={onInvestigate} customRules={customRules} onSaveDoc={onSaveDoc} settings={settings}/>)}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// AGENT CHAT
// ═══════════════════════════════════════════════════════════════════════════════

// Format Wazuh telemetry block for injection into the agent system prompt
function fmtTelemetry(tel){
  if(!tel)return"";
  const row=a=>`  [${(a.severity||"?").padEnd(8)}] ${(a.time||"").slice(0,19)} host=${a.host||"—"} src=${a.srcIp||"—"} rule=${(a.ruleName||"").slice(0,60)}`;
  const s=tel.stats||{};
  const lines=[`\nWAZUH TELEMETRY — LAST ${tel.timeframe_hours||48}H (as of ${(tel.queried_at||"").slice(0,19)}):`,
    `  host_events=${s.host_event_count||0} | ip_events=${s.ip_event_count||0} | rule_activations=${s.rule_activation_count||0}`,
    `  rule spread: ${s.rule_unique_hosts||0} host(s), ${s.rule_unique_src_ips||0} unique src IP(s)`,
    `  host severity: ${JSON.stringify(s.host_severity_breakdown||{})}`,
  ];
  if(tel.host_alerts?.length)lines.push(`\nHOST TIMELINE (${tel.host_alerts.length} events):`,
    ...tel.host_alerts.slice(0,15).map(row));
  if(tel.ip_alerts?.length)lines.push(`\nSOURCE IP HISTORY (${tel.ip_alerts.length} events):`,
    ...tel.ip_alerts.slice(0,10).map(row));
  if(tel.rule_alerts?.length)lines.push(`\nRULE FREQUENCY (${tel.rule_alerts.length} recent activations):`,
    ...tel.rule_alerts.slice(0,10).map(row));
  return lines.join("\n");
}

function AgentChat({rule,liveAlert,customRules,onBack,onSaveDoc}){
  const[messages,setMessages]=useState([]);const[input,setInput]=useState("");const[loading,setLoading]=useState(false);const[streaming,setStreaming]=useState("");
  const[extraCtx,setExtraCtx]=useState(null);
  const[telemetry,setTelemetry]=useState(null);
  const btm=useRef(null);
  const started=useRef(false);
  const allG=Object.values(STATIC_REG);
  const gc=allG.find(g=>g.rules.find(r=>r.id===rule?.id))?.color||(rule?.isCustom?"#22c55e":liveAlert?"#a855f7":"#38bdf8");
  const cb=customRules.length?`\nCUSTOM RULES IN SCOPE:\n${customRules.map(r=>`- [${r.id}] ${r.name} | ${r.tactic} | ${r.mitre} | Level:${r.level||"?"}`).join("\n")}` : "";

  function buildSYS(ctxAlerts,tel){
    if(liveAlert) return(
`You are an autonomous SOC incident responder analyzing a LIVE Wazuh SIEM detection. Stack: Cowrie/Dionaea honeypots | APTPACK IA/EXEC/PE/DISC/CA/STAGE | APT31 Sigma | iFrag-DHV RDP | Edge | Suricata+Zeek | YARA | IR playbooks: triage_collect.yml / containment_block_src.yml / ir_suricata_alert.yml / close_case.yml${cb}

LIVE WAZUH DETECTION:
  Alert ID:  ${liveAlert.id}
  Rule:      ${liveAlert.ruleName} (${liveAlert.ruleId}) — Level ${liveAlert.level||"?"} [${liveAlert.severity}]
  Timestamp: ${liveAlert.time}
  Tactic:    ${liveAlert.tactic} | MITRE: ${liveAlert.mitre}
  Groups:    ${(liveAlert.groups||[]).join(", ")||"—"}
  Decoder:   ${liveAlert.decoder||"—"}
  Location:  ${liveAlert.location||"—"}

ENDPOINT:
  Host:      ${liveAlert.host}
  Agent ID:  ${liveAlert.agentId||"—"}
  Agent IP:  ${liveAlert.agentIp||"—"}
  Account:   ${liveAlert.account}

NETWORK:
  src_ip:    ${liveAlert.srcIp}
  dst_ip:    ${liveAlert.dstIp}

IOCs:
${(liveAlert.iocs||[]).map(i=>`  [${i.t}] ${i.v}`).join("\n")||"  none extracted"}

RAW LOG:
  ${liveAlert.fullLog||"(not available)"}

Produce a FULL investigation report using EXACTLY this 7-section format:

1. Alert Summary — table with all metadata above
2. Timeline of Events — chronological phases with timestamps
3. Indicators of Compromise — Network IOCs table + Host-Based IOCs table
4. Kill Chain Mapping — MITRE ATT&CK stages mapped to observed activity
5. Risk Assessment — exploitability, success indicators, pivot risk, C2
6. Recommended Actions — ✅ completed / 🔴 urgent / 🟡 follow-up
7. Conclusion — confidence level and summary

${fmtTelemetry(tel)}
---
**🤖 AGENT READY:**
> \`pull logs\` \`hunt iocs\` \`expand ioc\` \`block ip\` \`correlate\` \`deploy ir\` \`export\` \`close case\``
    );
    const latest=ctxAlerts?.[0];
    return(
`You are an autonomous SOC agent on Wazuh SIEM. Stack: Cowrie/Dionaea honeypots | APTPACK IA/EXEC/PE/DISC/CA/STAGE | APT31 Sigma | iFrag-DHV RDP | Edge | Suricata+Zeek | YARA | IR playbooks: triage_collect.yml / containment_block_src.yml / ir_suricata_alert.yml / close_case.yml${cb}

DETECTION RULE:
  ID:       ${rule?.id}
  Name:     ${rule?.name}
  Severity: ${rule?.severity} | Tactic: ${rule?.tactic} | MITRE: ${rule?.mitre}${rule?.wazuhRuleId?`\n  Wazuh Rule ID: ${rule.wazuhRuleId} | Level: ${rule.level||"?"}`:""} ${rule?.playbook?`\n  Linked Playbook: ${rule.playbook.irId}`:""}
${latest?`
MOST RECENT LIVE DETECTION (Wazuh pipeline):
  Alert ID:  ${latest.id}
  Timestamp: ${latest.time}
  Host:      ${latest.host}
  Agent ID:  ${latest.agentId||"—"}
  Agent IP:  ${latest.agentIp||"—"}
  Account:   ${latest.account}
  src_ip:    ${latest.srcIp}
  dst_ip:    ${latest.dstIp}
  Groups:    ${(latest.groups||[]).join(", ")||"—"}
  Decoder:   ${latest.decoder||"—"}
  Location:  ${latest.location||"—"}
  IOCs:
${(latest.iocs||[]).map(i=>`    [${i.t}] ${i.v}`).join("\n")||"    none extracted"}
  RAW LOG:
    ${latest.fullLog||"(not available)"}
${ctxAlerts.length>1?`\nADDITIONAL RECENT DETECTIONS (${ctxAlerts.length-1}):\n${ctxAlerts.slice(1).map(a=>`  [${a.severity}] ${a.time} host=${a.host} src=${a.srcIp} account=${a.account} groups=${(a.groups||[]).join(",")||"—"}`).join("\n")}`:""}`:"\nNO RECENT LIVE DETECTIONS found for this rule in the Wazuh pipeline."}

Produce a FULL investigation report using EXACTLY this 7-section format:

1. Alert Summary — table with all detection metadata
2. Timeline of Events — chronological phases with timestamps (include any live detections found)
3. Indicators of Compromise — Network IOCs table + Host-Based IOCs table
4. Kill Chain Mapping — MITRE ATT&CK stages mapped to observed activity
5. Risk Assessment — exploitability, success indicators, pivot risk, C2
6. Recommended Actions — ✅ completed / 🔴 urgent / 🟡 follow-up
7. Conclusion — confidence level and summary

${fmtTelemetry(tel)}
---
**🤖 AGENT READY:**
> \`pull logs\` \`anomaly hunt\` \`attack chain\` \`run containment\` \`correlate\` \`export alert\` \`close case\``
    );
  }

  function buildInitMsg(ctxAlerts){
    if(liveAlert) return `LIVE ALERT — FULL INVESTIGATION REQUESTED:\n${formatAlertForAgent(liveAlert)}\n\nBegin full investigation using all real Wazuh observables above.`;
    if(ctxAlerts?.length) return `DETECTION RULE INVESTIGATION: ${rule?.id} — ${rule?.name}\n${rule?.severity} | ${rule?.tactic} | ${rule?.mitre}\n\nMOST RECENT LIVE DETECTION FROM WAZUH PIPELINE:\n${formatAlertForAgent(ctxAlerts[0])}\n\nBegin full investigation. Use the exact host, agent ID, source IP, groups, and raw log above to hunt this specific detection.`;
    return `DETECTION RULE INVESTIGATION: ${rule?.id} — ${rule?.name}\n${rule?.severity} | ${rule?.tactic} | ${rule?.mitre}\nNo recent live detections found in the pipeline for this rule. Provide investigation guidance, detection logic review, and hunt queries that can be run proactively.`;
  }

  // Fetch real Wazuh detections + full telemetry, then auto-trigger investigation
  useEffect(()=>{
    if(started.current)return;
    started.current=true;
    const ruleId=(rule?.wazuhRuleId||(rule?.id||"").replace(/^WAZ-/,"")).replace(/^CUSTOM-/,"");
    // Build telemetry query params from whatever observables we have
    const telQ=liveAlert
      ?`?host=${encodeURIComponent(liveAlert.host||"")}&src_ip=${encodeURIComponent(liveAlert.srcIp||"")}&agent_id=${encodeURIComponent(liveAlert.agentId||"")}&rule_id=${encodeURIComponent((liveAlert.ruleId||"").replace(/^WAZ-/,""))}`
      :`?rule_id=${encodeURIComponent(ruleId)}`;
    Promise.all([
      ruleId&&!liveAlert
        ?fetch(`/api/alerts/investigate?rule_id=${encodeURIComponent(ruleId)}&limit=5`).then(r=>r.json()).catch(()=>({alerts:[]}))
        :Promise.resolve({alerts:[]}),
      fetch(`/api/investigate/full${telQ}`).then(r=>r.json()).catch(()=>({telemetry:null})),
    ]).then(([alertsData,telData])=>{
      const alerts=(!liveAlert&&(alertsData.alerts||[]).length)?alertsData.alerts:null;
      const tel=telData?.telemetry||null;
      if(alerts)setExtraCtx(alerts);
      if(tel)setTelemetry(tel);
      runWithSys(buildInitMsg(alerts),buildSYS(alerts,tel));
    }).catch(()=>runWithSys(buildInitMsg(null),buildSYS(null,null)));
  },[]);

  useEffect(()=>{btm.current?.scrollIntoView({behavior:"smooth"});},[messages,streaming]);

  async function runWithSys(msg,sys){
    setLoading(true);setStreaming("");
    const next=[...messages,{role:"user",content:msg}];setMessages(next);
    let full="";
    await callAgent("investigate",next,c=>{full=c;setStreaming(c);},{system:sys});
    setStreaming("");
    setMessages([...next,{role:"assistant",content:full,at:ts()}]);
    setLoading(false);
  }

  async function run(msg){
    await runWithSys(msg,buildSYS(extraCtx,telemetry));
  }

  const QUICK=liveAlert
    ? ["pull logs","hunt iocs","expand ioc","block ip","correlate","deploy ir","export alert","close case"]
    : ["pull logs","anomaly hunt","attack chain","run containment","correlate","export alert","close case"];

  const headerTitle = liveAlert ? liveAlert.ruleName : (rule?.name||"Investigation");
  const headerSev = liveAlert ? liveAlert.severity : rule?.severity;
  const headerTactic = liveAlert ? liveAlert.tactic : rule?.tactic;

  return(
    <div style={{display:"flex",flexDirection:"column",height:"100vh",background:"#020817"}}>
      <style>{`@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}`}</style>
      <div style={{background:"#0a1628",borderBottom:`1px solid ${gc}33`,padding:"10px 18px",display:"flex",alignItems:"center",gap:12,flexShrink:0}}>
        <button onClick={onBack} style={{background:"none",border:"1px solid #1e293b",color:"#64748b",borderRadius:6,padding:"5px 11px",cursor:"pointer",fontSize:"0.72rem",fontFamily:"monospace"}}>← BACK</button>
        {liveAlert&&<span style={{background:"#a855f720",border:"1px solid #a855f755",color:"#a855f7",padding:"2px 10px",borderRadius:4,fontSize:"0.67rem",fontFamily:"monospace",fontWeight:700,letterSpacing:1}}>LIVE DETECTION</span>}
        {!liveAlert&&extraCtx&&<span style={{background:"#22c55e15",border:"1px solid #22c55e44",color:"#22c55e",padding:"2px 10px",borderRadius:4,fontSize:"0.67rem",fontFamily:"monospace",fontWeight:700,letterSpacing:1}}>LIVE DATA · {extraCtx.length} DETECTIONS</span>}
        <div style={{width:3,height:28,background:gc,borderRadius:2}}/>
        <div style={{flex:1}}>
          <div style={{color:"#f1f5f9",fontFamily:"'Oxanium',monospace",fontWeight:700,fontSize:"0.84rem"}}>{headerTitle}{rule?.isCustom&&<span style={{background:"#22c55e20",border:"1px solid #22c55e44",color:"#22c55e",padding:"0 6px",borderRadius:3,fontSize:"0.6rem",marginLeft:8}}>CUSTOM</span>}</div>
          <div style={{display:"flex",gap:6,marginTop:2}}><SB l={headerSev}/><TB t={headerTactic}/>
            {liveAlert&&<code style={{color:"#334155",fontSize:"0.62rem",fontFamily:"monospace"}}>{liveAlert.id}</code>}
            {liveAlert&&liveAlert.host!=="—"&&<code style={{color:"#38bdf8",fontSize:"0.62rem",fontFamily:"monospace"}}>host:{liveAlert.host}</code>}
            {liveAlert&&liveAlert.srcIp!=="—"&&<code style={{color:"#f97316",fontSize:"0.62rem",fontFamily:"monospace"}}>src:{liveAlert.srcIp}</code>}
          </div>
        </div>
        <div>{loading?<span style={{color:gc,fontSize:"0.67rem",fontFamily:"monospace",animation:"pulse 1.5s infinite"}}>● RUNNING</span>:<span style={{color:"#22c55e",fontSize:"0.67rem",fontFamily:"monospace"}}>● READY</span>}</div>
      </div>
      <div style={{flex:1,overflowY:"auto",padding:"12px 18px",display:"flex",flexDirection:"column",gap:10}}>
        {messages.map((m,i)=>(<div key={i}>
          {m.role==="user"&&i>0&&<div style={{display:"flex",justifyContent:"flex-end"}}><div style={{background:"#0f2a3a",border:`1px solid ${gc}33`,borderRadius:"10px 10px 2px 10px",padding:"7px 12px",maxWidth:"65%",color:"#cbd5e1",fontSize:"0.73rem",fontFamily:"monospace"}}>{m.content}</div></div>}
          {m.role==="assistant"&&m.content&&<div style={{background:"#080f1e",border:"1px solid #1e293b",borderRadius:"2px 10px 10px 10px",padding:"12px 14px"}}><div style={{color:gc,fontSize:"0.64rem",fontFamily:"monospace",marginBottom:7}}>⚡ OPXDR · {m.at||ts()}</div><MD text={m.content} color={gc}/></div>}
        </div>))}
        {loading&&!streaming&&<div style={{background:"#080f1e",border:`1px solid ${gc}44`,borderRadius:"2px 10px 10px 10px",padding:"12px 14px"}}><div style={{color:gc,fontSize:"0.64rem",fontFamily:"monospace",marginBottom:7,animation:"pulse 1.5s infinite"}}>⚡ ANALYZING... (model warming up — may take 1-2 min)</div></div>}
        {streaming&&<div style={{background:"#080f1e",border:`1px solid ${gc}44`,borderRadius:"2px 10px 10px 10px",padding:"12px 14px"}}><div style={{color:gc,fontSize:"0.64rem",fontFamily:"monospace",marginBottom:7}}>⚡ ANALYZING...</div><MD text={streaming} color={gc}/><span style={{color:gc,animation:"blink 1s infinite"}}>▋</span></div>}
        <div ref={btm}/>
      </div>
      {!loading&&messages.some(m=>m.role==="assistant"&&(m.content||"").trim().length>40)&&(
        <div style={{padding:"8px 18px",background:"#060d1a",borderTop:"1px solid #22c55e33",display:"flex",gap:8,alignItems:"center",flexWrap:"wrap",flexShrink:0}}>
          <span style={{color:"#22c55e",fontSize:"0.63rem",fontFamily:"monospace",letterSpacing:1,display:"flex",alignItems:"center",gap:5}}>
            <span style={{color:"#22c55e",animation:"blink 2s step-end infinite"}}>✓</span> ANALYSIS COMPLETE — choose next action or continue chatting
          </span>
          <div style={{flex:1}}/>
          {onSaveDoc&&<button
            onClick={()=>onSaveDoc({type:"investigation",title:liveAlert?liveAlert.ruleName:(rule?.name||"Investigation"),alert:liveAlert||null,rule:rule||null,messages})}
            style={{background:"#22c55e20",border:"1px solid #22c55e55",color:"#22c55e",borderRadius:5,padding:"5px 13px",fontSize:"0.67rem",fontWeight:700,cursor:"pointer",fontFamily:"monospace"}}>
            💾 Save
          </button>}
          <button
            onClick={()=>run("Based on the investigation above, provide: (1) Top 3 immediate threat hunting queries using Wazuh/KQL/Sigma targeting this specific host, source IP, and rule groups; (2) IOC pivot and expansion steps for each confirmed IOC; (3) Anomaly detection queries for the agent; (4) Recommended next triage actions in priority order.")}
            style={{background:"#38bdf820",border:"1px solid #38bdf855",color:"#38bdf8",borderRadius:5,padding:"5px 13px",fontSize:"0.67rem",fontWeight:700,cursor:"pointer",fontFamily:"monospace"}}>
            🔍 Further Triage
          </button>
          <button
            onClick={()=>run("Generate a full Incident Response plan for this detection. Provide: ### 🚨 IR CLASSIFICATION — severity, IR case priority, and notification matrix; ### 📋 CONTAINMENT STEPS — exact shell/Ansible commands to block/isolate NOW; ### 🔍 EVIDENCE COLLECTION — forensic commands for memory, disk, network artifacts; ### 🧹 ERADICATION — how to fully remove the threat; ### 🔄 RECOVERY — steps to safely restore; ### 📝 IR PLAYBOOK REFERENCE — which playbook template to use and how to instantiate it. Be specific with commands, hostnames, and IPs from the alert.")}
            style={{background:"#f9731620",border:"1px solid #f9731655",color:"#f97316",borderRadius:5,padding:"5px 13px",fontSize:"0.67rem",fontWeight:700,cursor:"pointer",fontFamily:"monospace"}}>
            🚨 Recommend IR
          </button>
          {onSaveDoc&&<button
            onClick={()=>{onSaveDoc({type:"investigation",title:liveAlert?liveAlert.ruleName:(rule?.name||"Investigation"),alert:liveAlert||null,rule:rule||null,messages});onBack();}}
            style={{background:"#1e293b",border:"1px solid #334155",color:"#64748b",borderRadius:5,padding:"5px 13px",fontSize:"0.67rem",fontWeight:700,cursor:"pointer",fontFamily:"monospace"}}>
            💾 Save & Exit
          </button>}
        </div>
      )}
      <div style={{padding:"6px 18px",display:"flex",gap:5,flexWrap:"wrap",background:"#060d1a",borderTop:"1px solid #0f172a"}}>
        {QUICK.map(t=><button key={t} onClick={()=>setInput(t)} style={{background:"#0f172a",border:"1px solid #1e293b",color:"#64748b",borderRadius:5,padding:"3px 9px",fontSize:"0.67rem",cursor:"pointer",fontFamily:"monospace"}} onMouseEnter={e=>{e.target.style.borderColor=gc;e.target.style.color=gc;}} onMouseLeave={e=>{e.target.style.borderColor="#1e293b";e.target.style.color="#64748b";}}>{t}</button>)}
      </div>
      <div style={{padding:"9px 18px",background:"#060d1a",borderTop:"1px solid #0f172a",display:"flex",gap:7}}>
        <input value={input} onChange={e=>setInput(e.target.value)} onKeyDown={e=>e.key==="Enter"&&!loading&&input.trim()&&(run(input.trim()),setInput(""))} placeholder={liveAlert?"query: pull logs / hunt iocs / expand ioc / block ip / correlate...":"pull logs / anomaly hunt / attack chain / custom task..."} disabled={loading} style={{flex:1,background:"#0a1628",border:"1px solid #1e293b",borderRadius:7,color:"#e2e8f0",padding:"8px 12px",fontSize:"0.73rem",fontFamily:"'IBM Plex Mono',monospace",outline:"none"}} onFocus={e=>e.target.style.borderColor=gc} onBlur={e=>e.target.style.borderColor="#1e293b"}/>
        <button onClick={()=>{if(input.trim()&&!loading){run(input.trim());setInput("");}}} disabled={loading||!input.trim()} style={{background:loading?"#1e293b":gc,color:loading?"#475569":"#020817",border:"none",borderRadius:7,padding:"8px 15px",fontWeight:700,fontSize:"0.73rem",cursor:loading?"not-allowed":"pointer",fontFamily:"monospace",whiteSpace:"nowrap"}}>{loading?"...":"SEND ↵"}</button>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// RULE WRITER — tabs: Form | Raw XML | Raw YAML | Preview
// ═══════════════════════════════════════════════════════════════════════════════
const DECODERS=["json","syslog","windows_eventchannel","auditd","apache-errorlog","nginx","ossec","ssh","web-accesslog","firewall","cisco-ios","pam"];
const MITRE_OPTS=["T1059","T1059.001","T1059.003","T1078","T1078.001","T1078.004","T1110","T1110.001","T1110.003","T1021","T1021.001","T1021.002","T1046","T1018","T1027","T1036","T1055","T1068","T1547","T1547.001","T1562","T1562.002","T1070","T1114","T1213","T1041","T1048","T1030","T1071","T1071.001","T1573","T1190","T1203","T1566","T1566.001","T1200","T1583","T1498","T1555","T1539","T1005","T1098","T1595"];
const TACTIC_LIST=["Initial Access","Execution","Privilege Escalation","Lateral Movement","Credential Access","Discovery","Command & Control","Exfiltration","Collection","Persistence","Defense Evasion","Impact","Reconnaissance"];

function buildXML(f){
  const mitreIds=f.mitreTechniques.filter(Boolean).map(t=>`      <id>${t}</id>`).join("\n");
  const fields=f.fieldConditions.filter(c=>c.name&&c.value).map(c=>`    <field name="${c.name}"${c.negate?' negate="yes"':""} >${c.value}</field>`).join("\n");
  return `<!-- Generated by OPXDR -->
<!-- Rule ID: ${f.ruleId} | Level: ${f.level} | ${f.severity} -->
<group name="${f.groupName},">

  <rule id="${f.ruleId}" level="${f.level}"${f.frequency?` frequency="${f.frequency}"`:""}${f.timeframe?` timeframe="${f.timeframe}"`:""}${f.noalert?' noalert="1"':""}>
    ${f.decoderAs?`<decoded_as>${f.decoderAs}</decoded_as>`:""}
    ${f.ifSid?`<if_sid>${f.ifSid}</if_sid>`:""}
    ${f.ifMatchedSid?`<if_matched_sid>${f.ifMatchedSid}</if_matched_sid>`:""}
${fields?fields+"\n":""}    <description>${f.description||""}</description>
${mitreIds?`    <mitre>\n${mitreIds}\n    </mitre>`:""}
    <group>${f.groupName},${f.tactic.toLowerCase().replace(/ /g,"_")},</group>
  </rule>

</group>`.replace(/^\s{4}\n/gm,"");
}

function RuleWriter({onSave,onClose,existing}){
  const nid=String(200000+Math.floor(Math.random()*9000));
  const[wtab,setWtab]=useState("form"); // form | rawxml | rawpb | preview
  const[saving,setSaving]=useState(false);
  const[aiLoading,setAiLoading]=useState(false);
  const[aiSug,setAiSug]=useState("");
  const[valLoading,setValLoading]=useState(false);const[valReport,setValReport]=useState("");
  const[pbAiLoading,setPbAiLoading]=useState(false);const[pbAiSug,setPbAiSug]=useState("");

  const[f,setF]=useState({
    ruleId:existing?.wazuhRuleId||nid, level:existing?.level?.toString()||"12",
    severity:existing?.severity||"HIGH", description:existing?.description||"",
    groupName:existing?.group||"custom_detection", decoderAs:existing?.decoded||"json",
    ifSid:"", ifMatchedSid:"", tactic:existing?.tactic||"Initial Access",
    mitreTechniques:existing?.mitre?.split(",")||["T1078",""],
    fieldConditions:[{name:"",value:"",negate:false},{name:"",value:"",negate:false}],
    frequency:"", timeframe:"", noalert:false,
  });

  // Raw XML editor — starts with generated XML, user can freely edit
  const generatedXml=buildXML(f);
  const[rawXml,setRawXml]=useState(generatedXml);
  const[xmlSynced,setXmlSynced]=useState(true); // did user edit raw?

  // Sync raw XML when form changes (only if user hasn't manually edited raw)
  useEffect(()=>{ if(xmlSynced) setRawXml(buildXML(f)); },[f,xmlSynced]);

  // IR Playbook state
  const irId=genIRId();
  const[pb,setPb]=useState({
    irId, title:f.description||"Custom Detection IR Playbook", severity:f.severity,
    tactic:f.tactic, analyst:"", steps:getPBTemplate(f.tactic).steps.map(s=>({...s,done:false,notes:""})),
    notifications:{ciso:true,ir:true,legal:false,dpo:false},
    iocs:[{type:"IP",value:""},{type:"Hash",value:""}],
  });
  const generatedYAML=pbToYAML(pb,{id:`CUS-${f.ruleId}`,name:f.description,mitre:f.mitreTechniques.filter(Boolean).join(",")});
  const[rawYaml,setRawYaml]=useState(generatedYAML);
  const[yamlSynced,setYamlSynced]=useState(true);
  useEffect(()=>{ if(yamlSynced) setRawYaml(pbToYAML(pb,{id:`CUS-${f.ruleId}`,name:f.description,mitre:f.mitreTechniques.filter(Boolean).join(",")})); },[pb,f,yamlSynced]);

  useEffect(()=>{
    const tmpl=getPBTemplate(f.tactic);
    setPb(p=>({...p,tactic:f.tactic,severity:f.severity,title:f.description||p.title,steps:tmpl.steps.map(s=>({...s,done:false,notes:""}))}));
  },[f.tactic,f.severity,f.description]);

  function sf(k,v){setF(p=>({...p,[k]:v,severity:k==="level"?sevFromLevel(v):p.severity}));}
  function smt(i,v){const m=[...f.mitreTechniques];m[i]=v;setF(p=>({...p,mitreTechniques:m}));}
  function sfc(i,k,v){const c=[...f.fieldConditions];c[i]={...c[i],[k]:v};setF(p=>({...p,fieldConditions:c}));}

  // Parse raw XML back into form when user clicks "Apply XML"
  function applyRawXml(){
    const{extracted}=parseXML(rawXml);
    if(extracted.length>0){
      const r=extracted[0];
      setF(p=>({...p,ruleId:r.wazuhRuleId,level:String(r.level),severity:r.severity,description:r.description,groupName:r.group||p.groupName,decoderAs:r.decoded||p.decoderAs,tactic:r.tactic,mitreTechniques:r.mitre.split(",")}));
      setXmlSynced(true);
    }
  }

  async function handleAI(){
    if(!f.description)return;setAiLoading(true);setAiSug("");
    await callAgent("ruleAssistant",[{role:"user",content:`Detection: "${f.description}"\nTactic: ${f.tactic} | MITRE: ${f.mitreTechniques.filter(Boolean).join(",")}\nDecoder: ${f.decoderAs} | Level: ${f.level}\n\nProvide:\n1. Best <field name="..."> conditions (2-3 pairs with regex)\n2. Optimal level with justification\n3. Decoder recommendation\n4. if_sid chain from known Wazuh base rules\n5. frequency/timeframe if threshold rule needed\n6. Anti-bypass companion rule if Defense Evasion tactic`}],c=>setAiSug(c),{system:"You are a Wazuh SIEM detection engineer specializing in XML rule writing. Provide precise field conditions, level, decoder, if_sid chains. Be specific with regex values. Format: numbered list, concise."});
    setAiLoading(false);
  }

  async function handlePbAI(){
    if(!f.description)return;setPbAiLoading(true);setPbAiSug("");
    const iocList=pb.iocs.filter(i=>i.value).map(i=>`${i.type}: ${i.value}`).join(", ")||"none tracked yet";
    await callAgent("irPlaybook",[{role:"user",content:`Generate a complete IR playbook for:\nRule: "${f.description}"\nSeverity: ${f.severity} | Tactic: ${f.tactic} | MITRE: ${f.mitreTechniques.filter(Boolean).join(",")}\nIOCs: ${iocList}\nStack: Wazuh+Suricata+Zeek | IR Case: ${pb.irId}\nAnsible playbooks: triage_collect.yml, containment_block_src.yml, validate_correlation.yml, close_case.yml\n\nGenerate all 5 phases (IDENTIFICATION, CONTAINMENT, ERADICATION, RECOVERY, CLOSE) with specific Ansible commands, time estimates per phase, and tactic-specific steps.`}],c=>setPbAiSug(c),{system:"You are an IR specialist with NIST CSF and MITRE ATT&CK expertise. Generate a complete incident response playbook with all 5 phases. Include specific Ansible playbook commands with -e parameters filled in, estimated time per phase, regulatory flags (GDPR/SEC/GLBA) if applicable, and tactic-specific containment logic. Format with clear phase headers."});
    setPbAiLoading(false);
  }

  async function handleValidate(){
    if(!f.description)return;setValLoading(true);setValReport("");
    const finalXml=xmlSynced?buildXML(f):rawXml;
    const finalYaml=yamlSynced?pbToYAML(pb,{id:`CUS-${f.ruleId}`,name:f.description}):rawYaml;
    await callAgent("validate",[{role:"user",content:`Validate this Wazuh detection rule and IR playbook:\n\nXML:\n\`\`\`xml\n${finalXml}\n\`\`\`\n\nPlaybook YAML:\n\`\`\`yaml\n${finalYaml.slice(0,2000)}\n\`\`\`\n\nMetadata: Rule ID ${f.ruleId} | Level ${f.level} | ${f.tactic} | MITRE: ${f.mitreTechniques.filter(Boolean).join(",")} | Decoder: ${f.decoderAs}`}],c=>setValReport(c),{system:"You are a senior Wazuh detection engineer performing final gate review. Validate the XML rule and IR playbook YAML. Check: XML syntax, decoder compatibility, MITRE technique validity, level vs tactic severity, YAML syntax, all 5 phases present, unresolved {PLACEHOLDER} variables, regulatory flag appropriateness. Output a FINAL VALIDATION REPORT with Gate Status (✅ PASS / ⚠ WARNINGS / 🚫 BLOCKED) and specific actionable findings per category."});
    setValLoading(false);
  }

  function doSave(){
    setSaving(true);
    // Use raw XML if user edited it directly, otherwise use form-generated
    const finalXml = xmlSynced ? buildXML(f) : rawXml;
    const finalYaml = yamlSynced ? pbToYAML(pb,{id:`CUS-${f.ruleId}`,name:f.description}) : rawYaml;
    const rule={
      id:`CUS-${f.ruleId}`, file:`custom_rules_${new Date().toISOString().slice(0,10).replace(/-/g,"")}.xml`,
      name:f.description||`Custom Rule ${f.ruleId}`, tactic:f.tactic,
      mitre:f.mitreTechniques.filter(Boolean).join(","), severity:f.severity,
      wazuhRuleId:f.ruleId, level:parseInt(f.level), group:f.groupName,
      ioc:f.fieldConditions.filter(c=>c.name&&c.value).map(c=>`${c.name}:${c.value}`).join("; "),
      decoded:f.decoderAs, isCustom:true, importedAt:new Date().toISOString(), groupLabel:"Custom Rules",
      xmlContent:finalXml, playbookYaml:finalYaml, playbook:pb,
    };

    // ── Save to backend: custom dir + /var/ossec/etc/rules/ + restart Wazuh ──
    fetch("/api/rules/custom", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ruleId: f.ruleId,
        name: f.description || `Custom Rule ${f.ruleId}`,
        severity: f.severity,
        tactic: f.tactic,
        mitre: f.mitreTechniques.filter(Boolean).join(","),
        group: f.groupName,
        xml: finalXml,
        yaml: finalYaml,
      }),
    })
      .then(r => r.json())
      .then(j => {
        console.log("[RuleWriter] saved to backend:", j);
        if (j.wazuh_error) console.warn("[RuleWriter] wazuh write issue:", j.wazuh_error);
        if (j.restart_error) console.warn("[RuleWriter] wazuh restart issue:", j.restart_error);
      })
      .catch(err => console.error("[RuleWriter] backend save failed:", err));

    setTimeout(()=>{onSave(rule);setSaving(false);},300);
  }

  const TABS=[{id:"form",label:"📝 Rule Editor"},{id:"irpb",label:"🚨 IR Playbook"},{id:"rawxml",label:"</> Raw XML"},{id:"rawpb",label:"📄 Raw YAML"},{id:"preview",label:"👁 Preview & Save"}];

  return(
    <div style={{position:"fixed",inset:0,background:"#000000dd",display:"flex",alignItems:"stretch",justifyContent:"center",zIndex:200,padding:"16px"}}>
      <div style={{background:"#0a1628",border:"1px solid #22c55e44",borderRadius:14,width:"min(1020px,98vw)",display:"flex",flexDirection:"column",overflow:"hidden",maxHeight:"97vh"}}>

        {/* Header */}
        <div style={{padding:"13px 20px",borderBottom:"1px solid #1e293b",display:"flex",alignItems:"center",justifyContent:"space-between",flexShrink:0}}>
          <div style={{display:"flex",alignItems:"center",gap:10}}>
            <span style={{fontSize:"1.2rem"}}>📝</span>
            <div>
              <div style={{color:"#22c55e",fontFamily:"'Oxanium',monospace",fontWeight:800,fontSize:"0.9rem",letterSpacing:1}}>RULE WRITER + IR PLAYBOOK</div>
              <div style={{color:"#334155",fontSize:"0.63rem",fontFamily:"monospace"}}>Author XML · Write YAML playbook · Preview · Register</div>
            </div>
            <SB l={f.severity}/>
          </div>
          <div style={{display:"flex",gap:8}}>
            <button onClick={doSave} disabled={!f.description||saving} style={{background:f.description?"#22c55e":"#1e293b",color:f.description?"#020817":"#475569",border:"none",borderRadius:7,padding:"7px 16px",fontWeight:700,fontSize:"0.74rem",cursor:f.description?"pointer":"not-allowed",fontFamily:"monospace"}}>{saving?"SAVING...":"✓ SAVE & REGISTER"}</button>
            <button onClick={onClose} style={{background:"none",border:"1px solid #1e293b",color:"#64748b",borderRadius:7,padding:"7px 12px",cursor:"pointer",fontSize:"0.73rem",fontFamily:"monospace"}}>✕</button>
          </div>
        </div>

        {/* Tabs */}
        <div style={{display:"flex",borderBottom:"1px solid #1e293b",background:"#060d1a",flexShrink:0}}>
          {TABS.map(t=><button key={t.id} onClick={()=>setWtab(t.id)} style={{background:"none",border:"none",borderBottom:wtab===t.id?"2px solid #22c55e":"2px solid transparent",color:wtab===t.id?"#22c55e":"#475569",padding:"9px 18px",cursor:"pointer",fontSize:"0.74rem",fontFamily:"monospace",fontWeight:wtab===t.id?700:400,transition:"all 0.15s"}}>{t.label}</button>)}
          <div style={{flex:1}}/>
          <div style={{display:"flex",alignItems:"center",gap:8,padding:"0 16px",fontSize:"0.63rem",fontFamily:"monospace",color:"#334155"}}>
            <span>Rule:</span><code style={{color:"#22c55e"}}>{f.ruleId}</code>
            <span>·</span><code style={{color:"#64748b"}}>Level {f.level}</code>
            {!xmlSynced&&<span style={{color:"#fbbf24",fontSize:"0.61rem"}}>⚠ RAW XML EDITED</span>}
          </div>
        </div>

        {/* Content */}
        <div style={{flex:1,overflowY:"auto"}}>

          {/* ── FORM TAB ── */}
          {wtab==="form"&&(
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:0}}>
              <div style={{padding:18,borderRight:"1px solid #1e293b",overflowY:"auto"}}>
                <div style={{color:"#22c55e",fontSize:"0.66rem",fontFamily:"monospace",letterSpacing:2,marginBottom:12}}>RULE METADATA</div>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:12}}>
                  <div><label style={lbl}>RULE ID</label><input style={inp()} value={f.ruleId} onChange={e=>sf("ruleId",e.target.value)}/></div>
                  <div><label style={lbl}>LEVEL (1–15)</label><input style={inp()} type="number" min="1" max="15" value={f.level} onChange={e=>sf("level",e.target.value)}/></div>
                </div>
                <div style={{marginBottom:12}}><label style={lbl}>DESCRIPTION *</label><input style={inp()} placeholder="Suspicious network logon — lateral movement indicator" value={f.description} onChange={e=>sf("description",e.target.value)}/></div>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:12}}>
                  <div><label style={lbl}>GROUP NAME</label><input style={inp()} value={f.groupName} onChange={e=>sf("groupName",e.target.value)}/></div>
                  <div><label style={lbl}>DECODER</label><select style={{...inp(),cursor:"pointer"}} value={f.decoderAs} onChange={e=>sf("decoderAs",e.target.value)}>{DECODERS.map(d=><option key={d}>{d}</option>)}</select></div>
                </div>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:12}}>
                  <div><label style={lbl}>IF SID</label><input style={inp()} placeholder="e.g. 5710" value={f.ifSid} onChange={e=>sf("ifSid",e.target.value)}/></div>
                  <div><label style={lbl}>IF MATCHED SID</label><input style={inp()} placeholder="threshold rules" value={f.ifMatchedSid} onChange={e=>sf("ifMatchedSid",e.target.value)}/></div>
                </div>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:12}}>
                  <div><label style={lbl}>FREQUENCY</label><input style={inp()} placeholder="e.g. 5" value={f.frequency} onChange={e=>sf("frequency",e.target.value)}/></div>
                  <div><label style={lbl}>TIMEFRAME (s)</label><input style={inp()} placeholder="e.g. 120" value={f.timeframe} onChange={e=>sf("timeframe",e.target.value)}/></div>
                </div>
                <hr style={{border:"none",borderTop:"1px solid #1e293b",margin:"12px 0"}}/>
                <div style={{color:"#22c55e",fontSize:"0.66rem",fontFamily:"monospace",letterSpacing:2,marginBottom:10}}>FIELD CONDITIONS</div>
                {f.fieldConditions.map((fc,i)=>(
                  <div key={i} style={{display:"grid",gridTemplateColumns:"1fr 1fr 56px",gap:7,marginBottom:7}}>
                    <input style={inp({fontSize:"0.71rem"})} placeholder="field name" value={fc.name} onChange={e=>sfc(i,"name",e.target.value)}/>
                    <input style={inp({fontSize:"0.71rem"})} placeholder="regex value" value={fc.value} onChange={e=>sfc(i,"value",e.target.value)}/>
                    <button onClick={()=>sfc(i,"negate",!fc.negate)} style={{background:fc.negate?"#ff000020":"#0f172a",border:`1px solid ${fc.negate?"#ff4444":"#1e293b"}`,color:fc.negate?"#ff6060":"#475569",borderRadius:5,cursor:"pointer",fontSize:"0.67rem",fontFamily:"monospace"}}>{fc.negate?"NOT":"="}</button>
                  </div>
                ))}
                <button onClick={()=>setF(p=>({...p,fieldConditions:[...p.fieldConditions,{name:"",value:"",negate:false}]}))} style={{background:"#0f172a",border:"1px dashed #1e293b",color:"#475569",borderRadius:5,padding:"4px 12px",fontSize:"0.68rem",cursor:"pointer",fontFamily:"monospace",width:"100%",marginBottom:12}}>+ Add Field</button>
                <hr style={{border:"none",borderTop:"1px solid #1e293b",margin:"12px 0"}}/>
                <div style={{color:"#22c55e",fontSize:"0.66rem",fontFamily:"monospace",letterSpacing:2,marginBottom:10}}>MITRE ATT&CK</div>
                <div style={{marginBottom:10}}><label style={lbl}>TACTIC</label><select style={{...inp(),cursor:"pointer"}} value={f.tactic} onChange={e=>sf("tactic",e.target.value)}>{TACTIC_LIST.map(t=><option key={t}>{t}</option>)}</select></div>
                <label style={lbl}>TECHNIQUES</label>
                {f.mitreTechniques.map((m,i)=>(
                  <div key={i} style={{display:"flex",gap:6,marginBottom:6}}>
                    <select style={{...inp({flex:1}),cursor:"pointer"}} value={m} onChange={e=>smt(i,e.target.value)}><option value="">-- select --</option>{MITRE_OPTS.map(t=><option key={t}>{t}</option>)}</select>
                    <button onClick={()=>setF(p=>({...p,mitreTechniques:p.mitreTechniques.filter((_,x)=>x!==i)}))} style={{background:"none",border:"1px solid #1e293b",color:"#475569",borderRadius:5,padding:"4px 9px",cursor:"pointer",fontSize:"0.7rem"}}>✕</button>
                  </div>
                ))}
                <button onClick={()=>setF(p=>({...p,mitreTechniques:[...p.mitreTechniques,""]}))} style={{background:"#0f172a",border:"1px dashed #1e293b",color:"#475569",borderRadius:5,padding:"4px 12px",fontSize:"0.68rem",cursor:"pointer",fontFamily:"monospace",width:"100%",marginTop:4}}>+ Add Technique</button>
              </div>
              {/* Right: AI assist + alert preview */}
              <div style={{padding:18,display:"flex",flexDirection:"column",gap:12}}>
                <div style={{color:"#38bdf8",fontSize:"0.66rem",fontFamily:"monospace",letterSpacing:2,display:"flex",alignItems:"center",gap:8}}>🤖 RULE WRITER AGENT<span style={{color:"#334155",fontSize:"0.6rem",fontFamily:"monospace",letterSpacing:0}}>DeepSeek Coder → Mistral fallback</span></div>
                <button onClick={handleAI} disabled={!f.description||aiLoading} style={{background:f.description&&!aiLoading?"#38bdf820":"#0f172a",border:`1px solid ${f.description&&!aiLoading?"#38bdf855":"#1e293b"}`,color:f.description&&!aiLoading?"#38bdf8":"#475569",borderRadius:7,padding:"8px",fontSize:"0.73rem",cursor:f.description&&!aiLoading?"pointer":"not-allowed",fontFamily:"monospace",fontWeight:700}}>{aiLoading?"⟳ Analyzing...":"⚡ AI SUGGEST FIELD CONDITIONS"}</button>
                {aiSug?(
                  <div style={{background:"#060d1a",border:"1px solid #38bdf833",borderRadius:8,padding:12,flex:1,overflowY:"auto"}}><MD text={aiSug} color="#38bdf8"/></div>
                ):(
                  <div style={{background:"#060d1a",border:"1px solid #1e293b",borderRadius:8,padding:12,flex:1,color:"#1e293b",fontSize:"0.7rem",fontFamily:"monospace",lineHeight:2}}>
                    {"// AI suggestions appear here\n// Field conditions · Level · Decoder · if_sid".split("\n").map((l,i)=><div key={i}>{l}</div>)}
                  </div>
                )}
                <div>
                  <div style={{color:"#334155",fontSize:"0.63rem",fontFamily:"monospace",letterSpacing:1,marginBottom:7}}>ALERT PREVIEW</div>
                  <div style={{background:"#060d1a",border:`1px solid ${(SEV[f.severity]||SEV.HIGH).border}44`,borderRadius:8,padding:"11px 13px",fontFamily:"'IBM Plex Mono',monospace",fontSize:"0.72rem"}}>
                    <div style={{display:"flex",justifyContent:"space-between",marginBottom:7}}><span style={{color:(SEV[f.severity]||SEV.HIGH).text,fontWeight:700,fontFamily:"'Oxanium',monospace"}}>{genAlertId(`CUS-${f.ruleId}`)}</span><SB l={f.severity}/></div>
                    <div style={{color:"#94a3b8",display:"grid",gridTemplateColumns:"80px 1fr",rowGap:3}}>
                      <span style={{color:"#334155"}}>rule:</span><span style={{color:"#e2e8f0"}}>{f.description||"<description>"}</span>
                      <span style={{color:"#334155"}}>decoder:</span><span style={{color:"#67e8f9"}}>{f.decoderAs}</span>
                    </div>
                    <div style={{marginTop:7,display:"flex",gap:5,flexWrap:"wrap"}}>{f.mitreTechniques.filter(Boolean).map(t=><code key={t} style={{background:"#0f172a",border:"1px solid #1e293b",color:"#79c0ff",padding:"1px 6px",borderRadius:3,fontSize:"0.64rem"}}>{t}</code>)}<TB t={f.tactic}/></div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ── IR PLAYBOOK TAB ── (interactive editor for `pb` state) */}
          {wtab==="irpb"&&(
            <div style={{padding:18}}>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16,marginBottom:18}}>
                {/* Left: IR case metadata */}
                <div>
                  <div style={{color:"#f97316",fontSize:"0.66rem",fontFamily:"monospace",letterSpacing:2,marginBottom:10}}>IR CASE METADATA</div>
                  <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:10}}>
                    <div><label style={lbl}>IR CASE ID</label><input style={inp({color:"#f97316"})} value={pb.irId} onChange={e=>setPb(p=>({...p,irId:e.target.value}))}/></div>
                    <div><label style={lbl}>ASSIGNED ANALYST</label><input style={inp()} placeholder="analyst@soc.local" value={pb.analyst} onChange={e=>setPb(p=>({...p,analyst:e.target.value}))}/></div>
                  </div>
                  <div style={{marginBottom:10}}>
                    <label style={lbl}>PLAYBOOK TITLE</label>
                    <input style={inp()} value={pb.title} onChange={e=>setPb(p=>({...p,title:e.target.value}))}/>
                  </div>
                  <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                    <SB l={pb.severity}/><TB t={pb.tactic}/>
                  </div>
                </div>

                {/* Right: notifications + IOCs */}
                <div>
                  <div style={{color:"#f97316",fontSize:"0.66rem",fontFamily:"monospace",letterSpacing:2,marginBottom:10}}>NOTIFICATIONS</div>
                  {Object.entries(pb.notifications).map(([k,v])=>(
                    <label key={k} style={{display:"flex",alignItems:"center",gap:8,marginBottom:7,cursor:"pointer"}}>
                      <input type="checkbox" checked={v} onChange={e=>setPb(p=>({...p,notifications:{...p.notifications,[k]:e.target.checked}}))} style={{accentColor:"#f97316"}}/>
                      <span style={{color:v?"#e2e8f0":"#475569",fontSize:"0.72rem",fontFamily:"monospace",textTransform:"uppercase",letterSpacing:1}}>
                        {k==="dpo"?"DPO (data breach)":k==="ciso"?"CISO":k==="ir"?"IR Team (Slack)":"Legal / Compliance"}
                      </span>
                    </label>
                  ))}
                  <div style={{marginTop:12}}>
                    <div style={{color:"#334155",fontSize:"0.63rem",fontFamily:"monospace",letterSpacing:1,marginBottom:6}}>IOC TRACKING</div>
                    {pb.iocs.map((ioc,i)=>(
                      <div key={i} style={{display:"grid",gridTemplateColumns:"80px 1fr 28px",gap:6,marginBottom:5}}>
                        <select style={{...inp({fontSize:"0.69rem"}),cursor:"pointer"}} value={ioc.type} onChange={e=>{const iocs=[...pb.iocs];iocs[i]={...iocs[i],type:e.target.value};setPb(p=>({...p,iocs}));}}>
                          {["IP","Domain","Hash","URL","Account","Host"].map(t=><option key={t}>{t}</option>)}
                        </select>
                        <input style={inp({fontSize:"0.7rem"})} placeholder={`${ioc.type} value...`} value={ioc.value} onChange={e=>{const iocs=[...pb.iocs];iocs[i]={...iocs[i],value:e.target.value};setPb(p=>({...p,iocs}));}}/>
                        <button onClick={()=>setPb(p=>({...p,iocs:p.iocs.filter((_,x)=>x!==i)}))} style={{background:"none",border:"1px solid #1e293b",color:"#475569",borderRadius:5,cursor:"pointer",fontSize:"0.7rem"}}>✕</button>
                      </div>
                    ))}
                    <button onClick={()=>setPb(p=>({...p,iocs:[...p.iocs,{type:"IP",value:""}]}))} style={{background:"#0f172a",border:"1px dashed #1e293b",color:"#475569",borderRadius:5,padding:"4px 12px",fontSize:"0.67rem",cursor:"pointer",fontFamily:"monospace"}}>+ Add IOC</button>
                  </div>
                </div>
              </div>

              {/* Response steps */}
              <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:10}}>
                <div style={{color:"#f97316",fontSize:"0.66rem",fontFamily:"monospace",letterSpacing:2}}>RESPONSE STEPS — tied to {f.tactic}</div>
                <span style={{color:"#475569",fontSize:"0.63rem",fontFamily:"monospace"}}>{pb.steps.filter(s=>s.done).length}/{pb.steps.length} complete</span>
              </div>
              {pb.steps.map((step,i)=>{
                const pc=PH_COL[step.phase]||"#64748b";
                return(
                  <div key={i} style={{background:"#060d1a",border:`1px solid ${pc}33`,borderRadius:8,padding:"11px 13px",marginBottom:8}}>
                    <div style={{display:"flex",alignItems:"flex-start",gap:10}}>
                      <input type="checkbox" checked={step.done} onChange={e=>{const steps=[...pb.steps];steps[i]={...steps[i],done:e.target.checked};setPb(p=>({...p,steps}));}} style={{accentColor:pc,marginTop:3,flexShrink:0}}/>
                      <div style={{flex:1,minWidth:0}}>
                        <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:5,flexWrap:"wrap"}}>
                          <select value={step.phase} onChange={e=>{const steps=[...pb.steps];steps[i]={...steps[i],phase:e.target.value};setPb(p=>({...p,steps}));}}
                            style={{background:pc+"20",border:`1px solid ${pc}55`,color:pc,padding:"1px 7px",borderRadius:3,fontSize:"0.64rem",fontFamily:"monospace",cursor:"pointer",outline:"none"}}>
                            {Object.keys(PH_COL).map(ph=><option key={ph} value={ph} style={{background:"#0a1628",color:"#e2e8f0"}}>{ph}</option>)}
                          </select>
                          <input value={step.action} onChange={e=>{const steps=[...pb.steps];steps[i]={...steps[i],action:e.target.value};setPb(p=>({...p,steps}));}}
                            style={{flex:1,minWidth:200,background:"transparent",border:"none",color:step.done?"#475569":"#e2e8f0",fontSize:"0.74rem",fontFamily:"monospace",textDecoration:step.done?"line-through":"none",outline:"none",padding:"2px 4px"}}/>
                          <button onClick={()=>setPb(p=>({...p,steps:p.steps.filter((_,x)=>x!==i)}))} style={{background:"none",border:"1px solid #1e293b",color:"#475569",borderRadius:4,padding:"1px 7px",cursor:"pointer",fontSize:"0.65rem",fontFamily:"monospace"}}>✕</button>
                        </div>
                        <textarea value={step.cmd} onChange={e=>{const steps=[...pb.steps];steps[i]={...steps[i],cmd:e.target.value};setPb(p=>({...p,steps}));}}
                          rows={Math.min(6,Math.max(1,(step.cmd||"").split("\n").length))} spellCheck={false}
                          style={{width:"100%",background:"#0a1628",border:"1px solid #1e293b",borderRadius:5,padding:"6px 9px",color:"#67e8f9",fontSize:"0.67rem",fontFamily:"'IBM Plex Mono',monospace",lineHeight:1.6,marginBottom:5,outline:"none",resize:"vertical"}}/>
                        <input style={inp({fontSize:"0.69rem",padding:"4px 9px"})} placeholder="Analyst notes for this step..." value={step.notes} onChange={e=>{const steps=[...pb.steps];steps[i]={...steps[i],notes:e.target.value};setPb(p=>({...p,steps}));}}/>
                      </div>
                    </div>
                  </div>
                );
              })}
              <button onClick={()=>setPb(p=>({...p,steps:[...p.steps,{phase:"IDENTIFICATION",action:"",cmd:"",done:false,notes:""}]}))}
                style={{background:"#0f172a",border:"1px dashed #1e293b",color:"#475569",borderRadius:6,padding:"7px",fontSize:"0.71rem",cursor:"pointer",fontFamily:"monospace",width:"100%",marginTop:4}}>+ Add Custom Step</button>
              <div style={{marginTop:12,display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
                <button onClick={()=>{const tmpl=getPBTemplate(f.tactic);setPb(p=>({...p,steps:tmpl.steps.map(s=>({...s,done:false,notes:""}))}));}} style={{background:"#0f172a",border:"1px solid #1e293b",color:"#64748b",borderRadius:6,padding:"5px 13px",fontSize:"0.69rem",cursor:"pointer",fontFamily:"monospace"}}>↺ Reload Template</button>
                <button onClick={handlePbAI} disabled={pbAiLoading||!f.description} style={{background:pbAiLoading?"#0f172a":"#f9731620",border:`1px solid ${pbAiLoading?"#1e293b":"#f9731655"}`,color:pbAiLoading?"#475569":"#f97316",borderRadius:6,padding:"5px 13px",fontSize:"0.69rem",cursor:pbAiLoading||!f.description?"not-allowed":"pointer",fontFamily:"monospace",fontWeight:700}}>{pbAiLoading?"⟳ Generating...":"🤖 AI Generate Playbook"}</button>
                <span style={{color:"#475569",fontSize:"0.65rem",fontFamily:"monospace"}}>Steps + IOCs + notifications save into the YAML on register.</span>
              </div>
              {pbAiSug&&(
                <div style={{marginTop:12,background:"#060d1a",border:"1px solid #f9731833",borderRadius:8,padding:"12px 14px"}}>
                  <div style={{color:"#f97316",fontSize:"0.65rem",fontFamily:"monospace",marginBottom:8,letterSpacing:1}}>🤖 IR PLAYBOOK AGENT — Mistral Large · Review suggestions and copy steps above</div>
                  <MD text={pbAiSug} color="#f97316"/>
                </div>
              )}
            </div>
          )}

          {/* ── RAW XML TAB ── */}
          {wtab==="rawxml"&&(
            <div style={{padding:18}}>
              <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:10}}>
                <div>
                  <div style={{color:"#22c55e",fontSize:"0.66rem",fontFamily:"monospace",letterSpacing:2}}>RAW WAZUH XML EDITOR</div>
                  <div style={{color:"#475569",fontSize:"0.63rem",fontFamily:"monospace",marginTop:2}}>Edit directly in the correct format. Click Apply to sync back to form fields.</div>
                </div>
                <div style={{display:"flex",gap:8}}>
                  <button onClick={()=>{setRawXml(buildXML(f));setXmlSynced(true);}} style={{background:"#0f172a",border:"1px solid #1e293b",color:"#64748b",borderRadius:6,padding:"5px 13px",fontSize:"0.7rem",cursor:"pointer",fontFamily:"monospace"}}>↺ Reset from Form</button>
                  <button onClick={applyRawXml} style={{background:"#22c55e20",border:"1px solid #22c55e55",color:"#22c55e",borderRadius:6,padding:"5px 13px",fontSize:"0.7rem",fontWeight:700,cursor:"pointer",fontFamily:"monospace"}}>✓ Apply XML → Form</button>
                </div>
              </div>
              <textarea
                value={rawXml}
                onChange={e=>{setRawXml(e.target.value);setXmlSynced(false);}}
                spellCheck={false}
                style={{width:"100%",height:"calc(100vh - 340px)",minHeight:420,background:"#060d1a",border:`1px solid ${xmlSynced?"#1e293b":"#fbbf2466"}`,borderRadius:8,color:"#67e8f9",padding:16,fontSize:"0.74rem",fontFamily:"'IBM Plex Mono',monospace",outline:"none",resize:"vertical",lineHeight:1.7,tabSize:2}}
              />
              {!xmlSynced&&<div style={{marginTop:6,color:"#fbbf24",fontSize:"0.68rem",fontFamily:"monospace"}}>⚠ Raw XML has been manually edited — form fields may not reflect this. Click "Apply XML → Form" to sync.</div>}
            </div>
          )}

          {/* ── RAW YAML PLAYBOOK TAB ── */}
          {wtab==="rawpb"&&(
            <div style={{padding:18}}>
              <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:10}}>
                <div>
                  <div style={{color:"#f97316",fontSize:"0.66rem",fontFamily:"monospace",letterSpacing:2}}>RAW IR PLAYBOOK YAML EDITOR</div>
                  <div style={{color:"#475569",fontSize:"0.63rem",fontFamily:"monospace",marginTop:2}}>Edit the IR playbook directly in YAML. This is saved alongside the rule on register.</div>
                </div>
                <div style={{display:"flex",gap:8}}>
                  <button onClick={()=>{setRawYaml(pbToYAML(pb,{id:`CUS-${f.ruleId}`,name:f.description,mitre:f.mitreTechniques.filter(Boolean).join(",")}));setYamlSynced(true);}} style={{background:"#0f172a",border:"1px solid #1e293b",color:"#64748b",borderRadius:6,padding:"5px 13px",fontSize:"0.7rem",cursor:"pointer",fontFamily:"monospace"}}>↺ Regenerate from Form</button>
                  <button onClick={()=>navigator.clipboard?.writeText(rawYaml)} style={{background:"#f9731620",border:"1px solid #f9731644",color:"#f97316",borderRadius:6,padding:"5px 13px",fontSize:"0.7rem",cursor:"pointer",fontFamily:"monospace"}}>📋 Copy YAML</button>
                </div>
              </div>
              <textarea
                value={rawYaml}
                onChange={e=>{setRawYaml(e.target.value);setYamlSynced(false);}}
                spellCheck={false}
                style={{width:"100%",height:"calc(100vh - 340px)",minHeight:420,background:"#060d1a",border:`1px solid ${yamlSynced?"#1e293b":"#f9731666"}`,borderRadius:8,color:"#93c5fd",padding:16,fontSize:"0.74rem",fontFamily:"'IBM Plex Mono',monospace",outline:"none",resize:"vertical",lineHeight:1.7,tabSize:2}}
              />
              {!yamlSynced&&<div style={{marginTop:6,color:"#f97316",fontSize:"0.68rem",fontFamily:"monospace"}}>⚠ YAML manually edited — regenerate from form to reset.</div>}
            </div>
          )}

          {/* ── PREVIEW & SAVE TAB ── */}
          {wtab==="preview"&&(
            <div style={{padding:18,display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
              <div>
                <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:8}}>
                  <div style={{color:"#22c55e",fontSize:"0.66rem",fontFamily:"monospace",letterSpacing:2}}>WAZUH XML — EDITABLE</div>
                  <button onClick={()=>navigator.clipboard?.writeText(xmlSynced?buildXML(f):rawXml)} style={{background:"#22c55e20",border:"1px solid #22c55e44",color:"#22c55e",borderRadius:5,padding:"4px 12px",fontSize:"0.68rem",cursor:"pointer",fontFamily:"monospace"}}>📋 Copy</button>
                </div>
                <textarea
                  value={xmlSynced?buildXML(f):rawXml}
                  onChange={e=>{setRawXml(e.target.value);setXmlSynced(false);}}
                  spellCheck={false}
                  style={{width:"100%",height:"calc(50vh - 80px)",minHeight:300,background:"#060d1a",border:"1px solid #22c55e33",borderRadius:8,color:"#67e8f9",padding:14,fontSize:"0.72rem",fontFamily:"'IBM Plex Mono',monospace",outline:"none",resize:"vertical",lineHeight:1.7}}
                />
                {!xmlSynced&&<div style={{color:"#fbbf24",fontSize:"0.65rem",fontFamily:"monospace",marginTop:4}}>⚠ Contains manual edits</div>}
              </div>
              <div>
                <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:8}}>
                  <div style={{color:"#f97316",fontSize:"0.66rem",fontFamily:"monospace",letterSpacing:2}}>IR PLAYBOOK YAML — EDITABLE</div>
                  <button onClick={()=>navigator.clipboard?.writeText(yamlSynced?pbToYAML(pb,{id:`CUS-${f.ruleId}`,name:f.description}):rawYaml)} style={{background:"#f9731620",border:"1px solid #f9731644",color:"#f97316",borderRadius:5,padding:"4px 12px",fontSize:"0.68rem",cursor:"pointer",fontFamily:"monospace"}}>📋 Copy</button>
                </div>
                <textarea
                  value={yamlSynced?pbToYAML(pb,{id:`CUS-${f.ruleId}`,name:f.description,mitre:f.mitreTechniques.filter(Boolean).join(",")}):rawYaml}
                  onChange={e=>{setRawYaml(e.target.value);setYamlSynced(false);}}
                  spellCheck={false}
                  style={{width:"100%",height:"calc(50vh - 80px)",minHeight:300,background:"#060d1a",border:"1px solid #f9731633",borderRadius:8,color:"#93c5fd",padding:14,fontSize:"0.72rem",fontFamily:"'IBM Plex Mono',monospace",outline:"none",resize:"vertical",lineHeight:1.7}}
                />
                {!yamlSynced&&<div style={{color:"#f97316",fontSize:"0.65rem",fontFamily:"monospace",marginTop:4}}>⚠ Contains manual edits</div>}
              </div>
              {/* ── VALIDATION AGENT GATE ── */}
              <div style={{gridColumn:"1/-1",borderTop:"1px solid #1e293b",paddingTop:12,marginBottom:4}}>
                <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:valReport?10:0,flexWrap:"wrap"}}>
                  <button onClick={handleValidate} disabled={valLoading||!f.description} style={{background:valLoading?"#0f172a":valReport?"#a78bfa20":"#38bdf820",border:`1px solid ${valLoading?"#1e293b":valReport?"#a78bfa55":"#38bdf855"}`,color:valLoading?"#475569":valReport?"#a78bfa":"#38bdf8",borderRadius:6,padding:"6px 16px",fontSize:"0.71rem",fontWeight:700,cursor:valLoading||!f.description?"not-allowed":"pointer",fontFamily:"monospace"}}>{valLoading?"⟳ Validating...":valReport?"↺ Re-validate":"🔍 Validate with AI (Claude Sonnet)"}</button>
                  {valReport&&<span style={{color:"#475569",fontSize:"0.63rem",fontFamily:"monospace"}}>Validation Agent complete — review gate status before registering</span>}
                  {!valReport&&!valLoading&&<span style={{color:"#334155",fontSize:"0.63rem",fontFamily:"monospace"}}>Run validation gate before registering to catch XML errors and playbook gaps</span>}
                </div>
                {valReport&&<div style={{background:"#060d1a",border:"1px solid #a78bfa33",borderRadius:8,padding:"12px 14px",maxHeight:300,overflowY:"auto"}}><MD text={valReport} color="#a78bfa"/></div>}
              </div>
              <div style={{gridColumn:"1/-1",display:"flex",gap:10,alignItems:"center",padding:"10px 0",borderTop:"1px solid #1e293b"}}>
                <div style={{color:"#475569",fontSize:"0.7rem",fontFamily:"monospace",flex:1}}>Rule <code style={{color:"#22c55e"}}>{f.ruleId}</code> · <code style={{color:"#64748b"}}>level {f.level}</code> · {f.tactic} · MITRE: {f.mitreTechniques.filter(Boolean).join(", ")}</div>
                <button onClick={doSave} disabled={!f.description||saving} style={{background:f.description?"#22c55e":"#1e293b",color:f.description?"#020817":"#475569",border:"none",borderRadius:7,padding:"9px 22px",fontWeight:800,fontSize:"0.76rem",cursor:f.description?"pointer":"not-allowed",fontFamily:"'Oxanium',monospace",letterSpacing:1}}>{saving?"SAVING...":"✓ SAVE & REGISTER RULE"}</button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── RULE ROW ─────────────────────────────────────────────────────────────────
function RuleRow({rule,gc,onSelect,onDelete,customRules}){
  const[h,setH]=useState(false);
  const[showInv,setShowInv]=useState(false);
  return(
    <div>
      <div onMouseEnter={()=>setH(true)} onMouseLeave={()=>setH(false)} style={{display:"grid",gridTemplateColumns:"100px 1fr 145px 100px 115px",alignItems:"center",gap:10,padding:"8px 16px",background:h||showInv?"#0a1628":"transparent",borderBottom:showInv?"none":"1px solid #0f172a",transition:"background 0.1s"}}>
        <code style={{color:gc,fontSize:"0.69rem",fontFamily:"monospace",cursor:"pointer"}} onClick={()=>onSelect(rule)}>{rule.id}</code>
        <div onClick={()=>onSelect(rule)} style={{cursor:"pointer"}}>
          <div style={{color:"#e2e8f0",fontSize:"0.75rem",fontFamily:"'Oxanium',monospace",display:"flex",alignItems:"center",gap:5}}>
            {rule.name}
            {rule.isCustom&&<span style={{background:"#22c55e20",border:"1px solid #22c55e44",color:"#22c55e",padding:"0 5px",borderRadius:3,fontSize:"0.59rem"}}>CUSTOM</span>}
            {rule.playbook&&<span style={{background:"#f9731620",border:"1px solid #f9731644",color:"#f97316",padding:"0 5px",borderRadius:3,fontSize:"0.59rem"}}>+IR</span>}
          </div>
          <div style={{color:"#334155",fontSize:"0.61rem",fontFamily:"monospace",marginTop:1}}>{rule.file}</div>
        </div>
        <div onClick={()=>onSelect(rule)} style={{cursor:"pointer"}}><TB t={rule.tactic}/></div>
        <code style={{color:"#334155",fontSize:"0.65rem",cursor:"pointer"}} onClick={()=>onSelect(rule)}>{rule.mitre.split(",")[0]}{rule.mitre.includes(",")?"…":""}</code>
        <div style={{display:"flex",gap:4,alignItems:"center",justifyContent:"flex-end"}}>
          <SB l={rule.severity}/>
          <button onClick={e=>{e.stopPropagation();setShowInv(v=>!v);}} title={showInv?"Close investigation":"Inline investigation"} style={{background:showInv?"#a855f730":"none",border:`1px solid ${showInv?"#a855f755":"#1e293b"}`,color:showInv?"#a855f7":"#475569",borderRadius:4,padding:"2px 7px",fontSize:"0.65rem",cursor:"pointer",fontFamily:"monospace",transition:"all 0.15s"}} onMouseEnter={e=>{if(!showInv){e.target.style.borderColor="#a855f755";e.target.style.color="#a855f7";}}} onMouseLeave={e=>{if(!showInv){e.target.style.borderColor="#1e293b";e.target.style.color="#475569";}}}>🔬</button>
          {rule.isCustom&&onDelete&&<button onClick={e=>{e.stopPropagation();onDelete(rule.id);}} style={{background:"none",border:"1px solid #ff444433",color:"#ff6060",borderRadius:4,padding:"1px 5px",fontSize:"0.61rem",cursor:"pointer",fontFamily:"monospace",opacity:0.5}} onMouseEnter={e=>e.target.style.opacity="1"} onMouseLeave={e=>e.target.style.opacity="0.5"}>✕</button>}
        </div>
      </div>
      {showInv&&(
        <div style={{padding:"0 16px 14px 16px",background:"#0a1628",borderBottom:"1px solid #0f172a"}}>
          <InlineAgentChat rule={rule} liveAlert={null} customRules={customRules||[]} gc={gc}/>
        </div>
      )}
    </div>
  );
}

// ─── Single investigation card — has its own inline chat state ────────────────
function InvestigationCard({a,done,onInvestigate,customRules}){
  const s=SEV[a.severity]||SEV.HIGH;
  return(
    <div style={{background:"#0a1117",border:`1px solid ${done?"#22c55e33":s.border+"33"}`,borderRadius:10,overflow:"hidden",marginBottom:10}}>
      <div style={{display:"flex"}}>
        <div style={{width:4,background:done?"#22c55e":s.border,flexShrink:0}}/>
        <div style={{flex:1,padding:"12px 14px"}}>
          {/* Header */}
          <div style={{display:"flex",alignItems:"flex-start",justifyContent:"space-between",marginBottom:8}}>
            <div style={{flex:1,minWidth:0}}>
              <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4,flexWrap:"wrap"}}>
                <span style={{color:"#e2e8f0",fontFamily:"'Oxanium',monospace",fontWeight:700,fontSize:"0.83rem"}}>{a.ruleName}</span>
                <SB l={a.severity}/>
                {done&&<span style={{background:"#22c55e20",border:"1px solid #22c55e44",color:"#22c55e",padding:"1px 7px",borderRadius:3,fontSize:"0.61rem",fontFamily:"monospace"}}>✓ INVESTIGATED</span>}
              </div>
              <div style={{display:"flex",gap:6,alignItems:"center",flexWrap:"wrap"}}>
                <code style={{color:"#334155",fontSize:"0.64rem",fontFamily:"monospace"}}>{a.ruleId}</code>
                <TB t={a.tactic}/>
                {(a.mitre||"—").split(",").filter(m=>m&&m!=="—").map(m=><code key={m} style={{background:"#0f172a",border:"1px solid #1e293b",color:"#79c0ff",padding:"1px 5px",borderRadius:3,fontSize:"0.63rem",fontFamily:"monospace"}}>{m}</code>)}
              </div>
            </div>
            <span style={{color:"#334155",fontSize:"0.67rem",fontFamily:"monospace",whiteSpace:"nowrap",marginLeft:10}}>{timeAgo(a.time)}</span>
          </div>
          {/* Observables grid */}
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(150px,1fr))",gap:5,marginBottom:8}}>
            {[
              {k:"host",v:a.host},
              {k:"src_ip",v:a.srcIp},
              {k:"dst_ip",v:a.dstIp},
              {k:"account",v:a.account},
              {k:"agent",v:a.agentId&&a.agentId!=="—"?`${a.agentId}@${a.agentIp||""}`:null},
              {k:"decoder",v:a.decoder&&a.decoder!=="—"?a.decoder:null},
              {k:"location",v:a.location&&a.location!=="—"?a.location:null},
            ].filter(({v})=>v&&v!=="—"&&v!=="— @ "&&v!=="—@").map(({k,v})=>(
              <div key={k} style={{background:"#060d1a",border:"1px solid #1e293b",borderRadius:5,padding:"4px 8px"}}>
                <div style={{color:"#475569",fontSize:"0.59rem",fontFamily:"monospace"}}>{k}</div>
                <div style={{color:"#e2e8f0",fontSize:"0.71rem",fontFamily:"monospace",wordBreak:"break-all"}}>{v}</div>
              </div>
            ))}
          </div>
          {/* IOCs */}
          {a.iocs&&a.iocs.length>0&&(
            <div style={{display:"flex",gap:5,flexWrap:"wrap",marginBottom:8,padding:"5px 8px",background:"#0d0208",border:"1px solid #fbbf2422",borderRadius:6}}>
              <span style={{color:"#475569",fontSize:"0.59rem",fontFamily:"monospace",alignSelf:"center",marginRight:2}}>IOC</span>
              {a.iocs.map((ioc,i)=>(
                <span key={i} style={{background:"#fbbf2412",border:"1px solid #fbbf2450",color:"#fcd34d",padding:"2px 8px",borderRadius:4,fontSize:"0.66rem",fontFamily:"monospace"}}>[{ioc.t}] {ioc.v}</span>
              ))}
            </div>
          )}
          {/* Raw log */}
          {a.fullLog&&(
            <div style={{marginBottom:8,padding:"4px 8px",background:"#060d1a",border:"1px solid #1e293b33",borderRadius:5}}>
              <div style={{color:"#475569",fontSize:"0.59rem",fontFamily:"monospace",marginBottom:2}}>raw_log</div>
              <div style={{color:"#64748b",fontSize:"0.64rem",fontFamily:"monospace",wordBreak:"break-all",whiteSpace:"pre-wrap"}}>{a.fullLog.slice(0,200)}{a.fullLog.length>200?"…":""}</div>
            </div>
          )}
          {/* Action */}
          <button onClick={()=>onInvestigate&&onInvestigate(a)} style={{background:done?"#22c55e20":"#a855f720",border:`1px solid ${done?"#22c55e55":"#a855f755"}`,color:done?"#22c55e":"#a855f7",borderRadius:6,padding:"6px 16px",fontSize:"0.72rem",fontWeight:700,cursor:"pointer",fontFamily:"monospace",letterSpacing:0.5}}>
            {done?"↻ Re-Investigate":"🔬 Run Investigation"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// AGENT INVESTIGATIONS TAB — real Wazuh detections only
// ═══════════════════════════════════════════════════════════════════════════════
const MEDIUM_PLUS=new Set(["CRITICAL","HIGH","MEDIUM"]);
const HIGH_PLUS=new Set(["CRITICAL","HIGH"]);
function InvestigationsTab({alerts,customRules,onInvestigate,investigated}){
  const[sevFilter,setSevFilter]=useState("ALL");
  const[sortBy,setSortBy]=useState("severity");
  const[searchQ,setSearchQ]=useState("");
  const sq=searchQ.toLowerCase();

  // Investigations shows HIGH and CRITICAL only — MEDIUM goes to live feed
  const items=alerts
    .filter(a=>HIGH_PLUS.has(a.severity))
    .filter(a=>sevFilter==="ALL"||a.severity===sevFilter)
    .filter(a=>!sq||(a.ruleName||"").toLowerCase().includes(sq)||(a.host||"").toLowerCase().includes(sq)||(a.srcIp||"").toLowerCase().includes(sq)||(a.ruleId||"").toLowerCase().includes(sq))
    .sort((a,b)=>{
      if(sortBy==="severity"){const o={CRITICAL:0,HIGH:1};const d=(o[a.severity]??2)-(o[b.severity]??2);return d!==0?d:new Date(b.time)-new Date(a.time);}
      return new Date(b.time)-new Date(a.time);
    });

  const counts={
    CRITICAL:alerts.filter(a=>a.severity==="CRITICAL").length,
    HIGH:alerts.filter(a=>a.severity==="HIGH").length,
    MEDIUM:alerts.filter(a=>a.severity==="MEDIUM").length,
    total:alerts.filter(a=>HIGH_PLUS.has(a.severity)).length,
  };

  return(
    <div style={{padding:"16px 24px"}}>
      {/* Stats */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:16}}>
        {[
          {l:"TOTAL HIGH+",v:counts.total,c:"#e2e8f0"},
          {l:"CRITICAL",v:counts.CRITICAL,c:"#ff6060"},
          {l:"HIGH",v:counts.HIGH,c:"#f97316"},
          {l:"MED · LIVE FEED",v:counts.MEDIUM,c:"#64748b"},
        ].map(({l,v,c})=>(
          <div key={l} style={{background:"#060d1a",border:"1px solid #1e293b",borderRadius:8,padding:"10px 14px"}}>
            <div style={{color:"#334155",fontSize:"0.62rem",fontFamily:"monospace",letterSpacing:1}}>{l}</div>
            <div style={{color:c,fontSize:"1.4rem",fontFamily:"'Oxanium',monospace",fontWeight:800,marginTop:3}}>{v}</div>
          </div>
        ))}
      </div>

      {/* Filter bar */}
      <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:14,flexWrap:"wrap"}}>
        <input value={searchQ} onChange={e=>setSearchQ(e.target.value)} placeholder="Search rule / host / IP..." style={{background:"#0a1628",border:"1px solid #1e293b",borderRadius:6,color:"#94a3b8",padding:"5px 12px",fontSize:"0.72rem",fontFamily:"monospace",outline:"none",width:260}}/>
        {["ALL","CRITICAL","HIGH"].map(s=>(
          <button key={s} onClick={()=>setSevFilter(s)} style={{background:sevFilter===s?"#1e3a5f":"#0a1628",border:`1px solid ${sevFilter===s?"#38bdf8":"#1e293b"}`,color:sevFilter===s?"#38bdf8":"#475569",borderRadius:5,padding:"4px 11px",fontSize:"0.67rem",fontFamily:"monospace",cursor:"pointer"}}>{s}</button>
        ))}
        <div style={{flex:1}}/>
        <span style={{color:"#334155",fontSize:"0.65rem",fontFamily:"monospace"}}>sort:</span>
        <select value={sortBy} onChange={e=>setSortBy(e.target.value)} style={{background:"#0a1628",border:"1px solid #1e293b",color:"#94a3b8",borderRadius:5,padding:"4px 9px",fontSize:"0.67rem",fontFamily:"monospace"}}>
          <option value="severity">Severity</option>
          <option value="time">Time</option>
        </select>
        <span style={{color:"#22c55e",fontSize:"0.65rem",fontFamily:"monospace",animation:"pulse 2s infinite"}}>● LIVE</span>
      </div>

      {items.length===0&&(
        <div style={{textAlign:"center",padding:"60px 20px",color:"#334155",fontFamily:"monospace",fontSize:"0.75rem"}}>
          <div style={{fontSize:"2rem",marginBottom:12}}>🛡️</div>
          <div>No Wazuh detections matching filter.</div>
          <div style={{marginTop:6,fontSize:"0.65rem",color:"#1e293b"}}>Alerts stream from /api/alerts/stream — verify Wazuh is sending events (min level {">"}= configured threshold).</div>
        </div>
      )}

      {items.map(a=>(
        <InvestigationCard key={a.id} a={a} done={investigated.has(a.id)} onInvestigate={onInvestigate} customRules={customRules}/>
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// DOCUMENTS TAB — saved investigations + reports
// ═══════════════════════════════════════════════════════════════════════════════
function DocumentsTab({docs,onDelete}){
  const[search,setSearch]=useState("");
  const[typeFilter,setTypeFilter]=useState("all");
  const[viewDoc,setViewDoc]=useState(null);
  const sq=search.toLowerCase();

  const filtered=[...docs]
    .filter(d=>typeFilter==="all"||d.type===typeFilter)
    .filter(d=>!sq||(d.title||"").toLowerCase().includes(sq)||(d.alert?.ruleName||"").toLowerCase().includes(sq)||(d.alert?.srcIp||"").toLowerCase().includes(sq)||(d.entry?.srcIP||"").toLowerCase().includes(sq))
    .sort((a,b)=>new Date(b.savedAt)-new Date(a.savedAt));

  const typeColor=t=>t==="investigation"?"#a855f7":"#38bdf8";
  const typeIcon=t=>t==="investigation"?"🔬":"📊";

  function exportText(doc){
    if(doc.type==="investigation"&&doc.messages)
      return(doc.messages||[]).filter(m=>m.role==="assistant").map(m=>m.content).join("\n\n---\n\n");
    if(doc.agentResult) return doc.agentResult;
    return doc.report||"";
  }

  return(
    <div style={{padding:"16px 24px"}}>
      {/* Stats bar */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:16}}>
        {[
          {l:"TOTAL SAVED",  v:docs.length,                                              c:"#e2e8f0"},
          {l:"INVESTIGATIONS",v:docs.filter(d=>d.type==="investigation").length,         c:"#a855f7"},
          {l:"REPORTS",      v:docs.filter(d=>d.type==="report").length,                 c:"#38bdf8"},
          {l:"CRITICAL",     v:docs.filter(d=>d.alert?.severity==="CRITICAL").length,    c:"#ff6060"},
        ].map(({l,v,c})=>(
          <div key={l} style={{background:"#060d1a",border:"1px solid #1e293b",borderRadius:8,padding:"10px 14px"}}>
            <div style={{color:"#334155",fontSize:"0.62rem",fontFamily:"monospace",letterSpacing:1}}>{l}</div>
            <div style={{color:c,fontSize:"1.4rem",fontFamily:"'Oxanium',monospace",fontWeight:800,marginTop:3}}>{v}</div>
          </div>
        ))}
      </div>

      {/* Filter bar */}
      <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:14,flexWrap:"wrap"}}>
        <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search title / rule / IP..."
          style={{background:"#0a1628",border:"1px solid #1e293b",borderRadius:6,color:"#94a3b8",padding:"5px 12px",fontSize:"0.72rem",fontFamily:"monospace",outline:"none",width:260}}/>
        {["all","investigation","report"].map(t=>(
          <button key={t} onClick={()=>setTypeFilter(t)} style={{background:typeFilter===t?"#1e3a5f":"#0a1628",border:`1px solid ${typeFilter===t?"#38bdf8":"#1e293b"}`,color:typeFilter===t?"#38bdf8":"#475569",borderRadius:5,padding:"4px 11px",fontSize:"0.67rem",fontFamily:"monospace",cursor:"pointer"}}>
            {t.toUpperCase()}
          </button>
        ))}
        <div style={{flex:1}}/>
        <span style={{color:"#334155",fontSize:"0.65rem",fontFamily:"monospace"}}>{filtered.length} document{filtered.length!==1?"s":""}</span>
      </div>

      {/* Empty state */}
      {filtered.length===0&&(
        <div style={{textAlign:"center",padding:"60px 20px",color:"#334155",fontFamily:"monospace",fontSize:"0.75rem"}}>
          <div style={{fontSize:"2rem",marginBottom:12}}>📁</div>
          <div>No saved documents.</div>
          <div style={{marginTop:6,fontSize:"0.65rem",color:"#1e293b"}}>Use 💾 Save Investigation (in Agent Chat) or 💾 Save Report (on alert cards) to save here.</div>
        </div>
      )}

      {/* Document cards */}
      {filtered.map(doc=>{
        const tc=typeColor(doc.type);
        return(
          <div key={doc.id} style={{background:"#0a1117",border:`1px solid ${tc}33`,borderRadius:10,overflow:"hidden",marginBottom:10}}>
            <div style={{display:"flex"}}>
              <div style={{width:4,background:tc,flexShrink:0}}/>
              <div style={{flex:1,padding:"12px 14px"}}>
                {/* Header row */}
                <div style={{display:"flex",alignItems:"flex-start",justifyContent:"space-between",marginBottom:8}}>
                  <div>
                    <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4,flexWrap:"wrap"}}>
                      <span style={{fontSize:"0.85rem"}}>{typeIcon(doc.type)}</span>
                      <span style={{color:"#e2e8f0",fontFamily:"'Oxanium',monospace",fontWeight:700,fontSize:"0.82rem"}}>{doc.title}</span>
                      <span style={{background:tc+"20",border:`1px solid ${tc}55`,color:tc,padding:"1px 7px",borderRadius:3,fontSize:"0.61rem",fontFamily:"monospace"}}>{doc.type.toUpperCase()}</span>
                      {doc.alert?.severity&&<SB l={doc.alert.severity}/>}
                    </div>
                    {doc.alert&&(
                      <div style={{display:"flex",gap:6,alignItems:"center",flexWrap:"wrap"}}>
                        <code style={{color:"#334155",fontSize:"0.63rem",fontFamily:"monospace"}}>{doc.alert.id}</code>
                        {doc.alert.tactic&&<TB t={doc.alert.tactic}/>}
                        {doc.alert.host&&doc.alert.host!=="—"&&<code style={{color:"#38bdf8",fontSize:"0.62rem",fontFamily:"monospace"}}>host:{doc.alert.host}</code>}
                        {doc.alert.srcIp&&doc.alert.srcIp!=="—"&&<code style={{color:"#f97316",fontSize:"0.62rem",fontFamily:"monospace"}}>src:{doc.alert.srcIp}</code>}
                      </div>
                    )}
                    {doc.entry&&(
                      <div style={{display:"flex",gap:6,alignItems:"center",flexWrap:"wrap"}}>
                        <code style={{color:"#334155",fontSize:"0.63rem",fontFamily:"monospace"}}>{doc.entry.type||""}</code>
                        {doc.entry.severity&&<SB l={doc.entry.severity}/>}
                        {doc.entry.srcIP&&<code style={{color:"#f97316",fontSize:"0.62rem",fontFamily:"monospace"}}>src:{doc.entry.srcIP}</code>}
                        {doc.entry.dstCountry&&<code style={{color:"#22c55e",fontSize:"0.62rem",fontFamily:"monospace"}}>dst:{doc.entry.dstCountry}</code>}
                        {doc.entry.cve&&doc.entry.cve!=="—"&&<code style={{color:"#fbbf24",fontSize:"0.62rem",fontFamily:"monospace"}}>cve:{doc.entry.cve}</code>}
                      </div>
                    )}
                  </div>
                  <span style={{color:"#334155",fontSize:"0.64rem",fontFamily:"monospace",whiteSpace:"nowrap",marginLeft:10}}>{new Date(doc.savedAt).toLocaleString()}</span>
                </div>

                {/* Metadata line */}
                {doc.type==="investigation"&&doc.messages&&(
                  <div style={{color:"#475569",fontSize:"0.63rem",fontFamily:"monospace",marginBottom:8}}>
                    {doc.messages.filter(m=>m.role==="assistant").length} agent response{doc.messages.filter(m=>m.role==="assistant").length!==1?"s":""} · {doc.messages.length} total messages
                  </div>
                )}
                {doc.type==="report"&&doc.report&&(
                  <div style={{color:"#64748b",fontSize:"0.65rem",fontFamily:"monospace",marginBottom:8,overflow:"hidden",maxHeight:48,lineHeight:1.5}}>
                    {doc.report.slice(0,220)}{doc.report.length>220?"…":""}
                  </div>
                )}

                {/* Actions */}
                <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
                  <button onClick={()=>setViewDoc(doc)} style={{background:`${tc}20`,border:`1px solid ${tc}55`,color:tc,borderRadius:6,padding:"4px 12px",fontSize:"0.69rem",fontWeight:700,cursor:"pointer",fontFamily:"monospace"}}>
                    👁 View
                  </button>
                  <button onClick={()=>navigator.clipboard?.writeText(exportText(doc))} style={{background:"#0f172a",border:"1px solid #1e293b",color:"#64748b",borderRadius:6,padding:"4px 12px",fontSize:"0.69rem",cursor:"pointer",fontFamily:"monospace"}}>
                    📋 Copy
                  </button>
                  <button onClick={()=>onDelete&&onDelete(doc.id)} style={{background:"none",border:"1px solid #1e293b",color:"#475569",borderRadius:6,padding:"4px 12px",fontSize:"0.69rem",cursor:"pointer",fontFamily:"monospace"}}>
                    ✕ Delete
                  </button>
                </div>
              </div>
            </div>
          </div>
        );
      })}

      {/* View Document Modal */}
      {viewDoc&&(
        <div style={{position:"fixed",inset:0,background:"#000000e0",display:"flex",alignItems:"center",justifyContent:"center",zIndex:300,padding:16}}>
          <div style={{background:"#0a1628",border:"1px solid #1e293b",borderRadius:12,width:"min(960px,96vw)",maxHeight:"92vh",display:"flex",flexDirection:"column",overflow:"hidden"}}>
            <div style={{padding:"12px 18px",borderBottom:"1px solid #1e293b",display:"flex",alignItems:"center",justifyContent:"space-between",flexShrink:0}}>
              <div>
                <div style={{color:"#e2e8f0",fontFamily:"'Oxanium',monospace",fontWeight:700,fontSize:"0.85rem"}}>{viewDoc.title}</div>
                <div style={{color:"#475569",fontSize:"0.63rem",fontFamily:"monospace",marginTop:2}}>Saved {new Date(viewDoc.savedAt).toLocaleString()} · {viewDoc.type}</div>
              </div>
              <div style={{display:"flex",gap:8}}>
                <button onClick={()=>navigator.clipboard?.writeText(exportText(viewDoc))} style={{background:"#1e293b",border:"none",color:"#94a3b8",borderRadius:6,padding:"6px 12px",fontSize:"0.7rem",cursor:"pointer",fontFamily:"monospace"}}>📋 Copy</button>
                <button onClick={()=>setViewDoc(null)} style={{background:"none",border:"1px solid #1e293b",color:"#64748b",borderRadius:6,padding:"6px 12px",cursor:"pointer",fontSize:"0.72rem",fontFamily:"monospace"}}>✕ Close</button>
              </div>
            </div>
            <div style={{flex:1,overflowY:"auto",padding:"16px 18px"}}>
              {viewDoc.type==="investigation"&&viewDoc.messages&&(
                <div style={{display:"flex",flexDirection:"column",gap:10}}>
                  {viewDoc.messages.map((m,i)=>(
                    <div key={i}>
                      {m.role==="user"&&i>0&&(
                        <div style={{display:"flex",justifyContent:"flex-end",marginBottom:4}}>
                          <span style={{background:"#0f2a3a",border:"1px solid #a855f733",borderRadius:"8px 8px 2px 8px",padding:"5px 10px",color:"#cbd5e1",fontSize:"0.69rem",fontFamily:"monospace",display:"inline-block",maxWidth:"70%"}}>{m.content.slice(0,400)}{m.content.length>400?"…":""}</span>
                        </div>
                      )}
                      {m.role==="assistant"&&(
                        <div style={{background:"#060d1a",border:"1px solid #a855f722",borderRadius:"2px 8px 8px 8px",padding:"10px 14px"}}>
                          <MD text={m.content} color="#a855f7"/>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
              {viewDoc.type==="investigation"&&!viewDoc.messages&&viewDoc.agentResult&&(
                <div style={{background:"#060d1a",border:"1px solid #a855f722",borderRadius:8,padding:"14px 16px"}}>
                  <MD text={viewDoc.agentResult} color="#a855f7"/>
                </div>
              )}
              {viewDoc.type==="report"&&(
                <div style={{background:"#060d1a",border:"1px solid #38bdf833",borderRadius:8,padding:"14px 16px"}}>
                  <MD text={viewDoc.report||""} color="#38bdf8"/>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN APP — NAV: Registry | Slack Alerts | [Agent Chat]
// ═══════════════════════════════════════════════════════════════════════════════
export default function App(){
  const[customRules,setCustomRules]=useState([]);
  const[slackAlerts,setSlackAlerts]=useState([]);
  const[liveRuleGroups,setLiveRuleGroups]=useState({}); // groups fetched from backend
  const[selected,setSelected]=useState(null);
  const[expanded,setExpanded]=useState(Object.keys(STATIC_REG));
  const[filter,setFilter]=useState("");
  const[modal,setModal]=useState(null);
  const[nav,setNav]=useState("registry"); // registry | slack | agent | documents | geointel
  const[time,setTime]=useState(new Date());
  const[backendStatus,setBackendStatus]=useState(null); // null | "ok" | "down"
  const[settings,setSettings]=useState({
    aiProvider:"none",slackEnabled:false,slackChannel:"#soc-alerts",
    autoAi:true,slackNotify:true,autoMinSev:"HIGH",
  });
  // Track which alert ids we've already auto-analyzed to avoid duplicate AI calls.
  const autoSeenRef=useRef(new Set());
  const[investigated,setInvestigated]=useState(new Set());
  const[savedDocs,setSavedDocs]=useState([]);

  // Listen for GeoIntel back navigation
  useEffect(() => {
    const handler = (e) => setNav(e.detail || "registry");
    window.addEventListener("opxdr-nav", handler);
    return () => window.removeEventListener("opxdr-nav", handler);
  }, []);

  // Load persisted custom rules from localStorage
  useEffect(()=>{dbLoad(SK_RULES).then(r=>{if(r)setCustomRules(r);});const t=setInterval(()=>setTime(new Date()),1000);return()=>clearInterval(t);},[]);
  useEffect(()=>{
    dbLoad(SK_DOCS).then(d=>{if(d)setSavedDocs(d);});
    fetch("/api/investigations").then(r=>r.json()).then(geoDocs=>{
      if(geoDocs&&geoDocs.length){
        setSavedDocs(prev=>{
          const existing=new Set(prev.map(d=>d.id));
          const merged=[...geoDocs.filter(d=>!existing.has(d.id)),...prev];
          dbSave(SK_DOCS,merged);
          return merged;
        });
      }
    }).catch(()=>{});
  },[]);

  // Pull AI/Slack capability flags from backend on mount
  useEffect(()=>{
    fetch("/api/settings").then(r=>r.json()).then(j=>{
      setSettings(s=>({
        ...s,
        aiProvider:j.ai_provider||"none",
        slackEnabled:!!j.slack_enabled,
        slackChannel:j.slack_channel||s.slackChannel,
        autoAi:s.autoAi&&j.ai_provider&&j.ai_provider!=="none",
        slackNotify:s.slackNotify&&!!j.slack_enabled,
      }));
    }).catch(()=>{});
  },[]);

  // Fetch live rules from backend on mount
  useEffect(()=>{
    fetch("/api/rules")
      .then(r=>r.json())
      .then(j=>{
        if(j.groups){
          setLiveRuleGroups(j.groups);
          // auto-expand any groups that came back
          setExpanded(prev=>{
            const newKeys=Object.keys(j.groups).filter(k=>!prev.includes(k));
            return newKeys.length?[...prev,...newKeys]:prev;
          });
        }
        setBackendStatus("ok");
      })
      .catch(()=>setBackendStatus("down"));
  },[]);

  // Load recent alerts from backend on mount (indexer or file fallback)
  useEffect(()=>{
    fetch("/api/alerts/recent?limit=500")
      .then(r=>r.json())
      .then(j=>{if(Array.isArray(j.alerts)&&j.alerts.length>0)setSlackAlerts(j.alerts.map(normalizeApiAlert));})
      .catch(()=>{});
  },[]);

  // SSE: stream live alerts from backend, append to slackAlerts.
  // Read settings via ref so the handler always sees the latest toggles
  // without needing to tear down/rebuild EventSource on every change.
  const settingsRef = useRef(settings);
  useEffect(()=>{settingsRef.current=settings;},[settings]);

  async function autoAnalyze(alert){
    if(autoSeenRef.current.has(alert.id))return;
    autoSeenRef.current.add(alert.id);
    const s=settingsRef.current;
    const sevOk=s.autoMinSev==="CRITICAL"
      ? alert.severity==="CRITICAL"
      : (alert.severity==="CRITICAL"||alert.severity==="HIGH");
    if(!s.autoAi||s.aiProvider==="none"||!sevOk)return;
    // Phase 1 — Log Analysis: normalize IOCs from raw Wazuh log
    setSlackAlerts(prev=>prev.map(a=>a.id===alert.id?{...a,reportLoading:true,reportPhase:"log-analysis"}:a));
    let logCtx="";
    try{
      logCtx=await callAgent("logAnalysis",[{role:"user",content:`Analyze this Wazuh alert and normalize all IOCs:\n${formatAlertForAgent(alert)}\n\nTasks:\n1. Classify each IOC: CONFIRMED/SUSPECTED/NOISE\n2. Classify event: BENIGN/SUSPICIOUS/MALICIOUS\n3. Identify MITRE phase and attack pattern\n4. Output a 3-sentence structured summary for the report agent.`}],()=>{},{system:"You are a SOC log analysis pre-processor (Llama 3.1 8B). Parse Wazuh alert metadata, normalize IOC fields from the raw log, classify each IOC and the overall event. Produce a concise 3-sentence summary: (1) event classification and confidence, (2) IOC classification, (3) recommended analyst action."});
    }catch(e){console.warn("[autoAnalyze logAnalysis]",e.message);}
    // Phase 2 — Full Investigation Report (Llama 3.1 70B)
    setSlackAlerts(prev=>prev.map(a=>a.id===alert.id?{...a,reportPhase:"report"}:a));
    try{
      const enriched=logCtx?`LOG ANALYSIS PRE-PROCESSOR (Llama 8B):\n${logCtx}\n\n---\n${formatAlertForAgent(alert)}`:formatAlertForAgent(alert);
      const report=await callAgent("slackReport",[{role:"user",content:enriched}],()=>{},{system:SLACK_AGENT_SYS(alert)});
      setSlackAlerts(prev=>prev.map(a=>a.id===alert.id?{...a,reportLoading:false,reportPhase:null,agentReport:{text:report,logCtx,at:ts()}}:a));
      if(s.slackNotify&&s.slackEnabled){
        try{await fetch("/api/slack/notify",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({alert,report})});}catch{}
      }
    }catch(e){
      setSlackAlerts(prev=>prev.map(a=>a.id===alert.id?{...a,reportLoading:false,reportPhase:null}:a));
    }
  }

  useEffect(()=>{
    let es;
    try {
      es = new EventSource("/api/alerts/stream");
      es.onmessage = (ev) => {
        try {
          const raw = JSON.parse(ev.data);
          if(raw && raw.id){
            const a = normalizeApiAlert(raw);
            setSlackAlerts(prev => {
              if(prev.some(x=>x.id===a.id))return prev;
              const next=[a,...prev];
              return next.length>500?next.slice(0,500):next;
            });
            autoAnalyze(a);
          }
        } catch {}
      };
      es.onerror = () => {}; // silent reconnect
    } catch {}
    return () => { if(es) es.close(); };
  },[]);

  async function handleSave(rule){
    const m=[...customRules,rule];
    setCustomRules(m);
    await dbSave(SK_RULES,m);
    if(!expanded.includes("custom"))setExpanded(p=>[...p,"custom"]);
    setModal(null);
    // Refresh live rules from backend so new rule shows in wazuh-fs group too
    try {
      const j = await fetch("/api/rules?refresh=1").then(r=>r.json());
      if(j.groups) setLiveRuleGroups(j.groups);
    } catch {}
  }
  async function handleDelete(id){
    const rule = customRules.find(r=>r.id===id);
    const n=customRules.filter(r=>r.id!==id);
    setCustomRules(n);
    await dbSave(SK_RULES,n);
    // Also tell backend to remove from disk + Wazuh
    if(rule && rule.file){
      try { await fetch(`/api/rules/custom/${encodeURIComponent(rule.file)}`,{method:"DELETE"}); } catch {}
    }
  }

  function saveDoc(docData){
    const doc={id:`DOC-${Date.now()}-${Math.random().toString(36).slice(2,6).toUpperCase()}`,savedAt:new Date().toISOString(),...docData};
    setSavedDocs(prev=>{const updated=[doc,...prev];dbSave(SK_DOCS,updated);return updated;});
    fetch("/api/investigations",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(doc)}).catch(()=>{});
  }
  function deleteDoc(id){
    setSavedDocs(prev=>{const updated=prev.filter(d=>d.id!==id);dbSave(SK_DOCS,updated);return updated;});
  }

  if(selected)return<AgentChat rule={selected.rule} liveAlert={selected.liveAlert||null} customRules={customRules} onBack={()=>setSelected(null)} onSaveDoc={saveDoc}/>;

  const fl=filter.toLowerCase();
  const totalAll=Object.values(STATIC_REG).reduce((s,g)=>s+g.rules.length,0)+customRules.length;
  const liveCount=Object.values(liveRuleGroups).reduce((s,g)=>s+(g.rules?g.rules.length:0),0);
  const critAlerts=slackAlerts.filter(a=>a.severity==="CRITICAL").length;

  // Merge: STATIC_REG + live backend groups + custom rules
  const fullReg={...STATIC_REG};
  // Add live backend groups (wazuh-fs, wazuh-api, botnets, etc.)
  for(const[k,g] of Object.entries(liveRuleGroups)){
    if(fullReg[k]){
      // Merge rules from backend into existing static group, avoiding duplicates by id
      const existingIds=new Set(fullReg[k].rules.map(r=>r.id));
      const newRules=(g.rules||[]).filter(r=>!existingIds.has(r.id));
      if(newRules.length) fullReg[k]={...fullReg[k],rules:[...fullReg[k].rules,...newRules]};
    } else {
      // New group entirely from backend
      fullReg[k]={
        label:g.label||k,
        color:g.color||"#64748b",
        icon:g.icon||"📂",
        rules:g.rules||[],
      };
    }
  }
  // Add custom rules group
  if(customRules.length>0){
    fullReg.custom={label:"Custom Rules (Authored & Imported)",color:"#22c55e",icon:"📝",rules:customRules,isCustomGroup:true};
  }

  const allStaticRules=Object.values(STATIC_REG).flatMap(g=>g.rules);
  const allLiveRules=Object.values(liveRuleGroups).flatMap(g=>g.rules||[]);
  function openAlertForInvestigation(alert){
    const foundRule=allStaticRules.find(r=>r.id===alert.ruleId)
      || allLiveRules.find(r=>r.id===alert.ruleId || r.wazuhRuleId===alert.ruleId?.replace("WAZ-",""))
      || {id:alert.ruleId,name:alert.ruleName,file:"live_alert.json",tactic:alert.tactic,mitre:alert.mitre,severity:alert.severity,isCustom:false};
    setSelected({rule:foundRule,liveAlert:alert});
  }
  function handleInvestigate(alert){
    openAlertForInvestigation(alert);
    setInvestigated(prev=>new Set([...prev,alert.id]));
  }

  return(
    <div style={{minHeight:"100vh",background:"#020817",color:"#e2e8f0"}}>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=Oxanium:wght@400;600;700;800&family=IBM+Plex+Mono:wght@400;500;700&display=swap');*{box-sizing:border-box;margin:0;padding:0;}::-webkit-scrollbar{width:5px;}::-webkit-scrollbar-track{background:#020817;}::-webkit-scrollbar-thumb{background:#1e293b;border-radius:3px;}@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}`}</style>

      {/* Top bar */}
      <div style={{background:"#060d1a",borderBottom:"1px solid #0f172a",padding:"0 24px",height:52,display:"flex",alignItems:"center",justifyContent:"space-between",flexShrink:0}}>
        <div style={{display:"flex",alignItems:"center",gap:12}}>
          <div style={{width:30,height:30,background:"linear-gradient(135deg,#38bdf8,#0ea5e9)",borderRadius:7,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"0.95rem"}}>⚡</div>
          <div>
            <div style={{fontFamily:"'Oxanium',monospace",fontWeight:800,fontSize:"0.88rem",letterSpacing:2,color:"#f1f5f9"}}>OPXDR</div>
            <div style={{color:"#334155",fontSize:"0.6rem",fontFamily:"monospace",letterSpacing:1}}>{totalAll} STATIC + {liveCount} LIVE RULES · {customRules.length} CUSTOM · {slackAlerts.length} ALERTS · {critAlerts} CRITICAL</div>
          </div>
        </div>
        <div style={{display:"flex",gap:10,alignItems:"center"}}>
          <div style={{display:"flex",gap:5}}>
            {["WAZUH","SURICATA","SIGMA","YARA"].map(s=><span key={s} style={{background:"#22c55e18",border:"1px solid #22c55e33",color:"#22c55e",padding:"2px 7px",borderRadius:3,fontSize:"0.6rem",fontFamily:"monospace"}}>● {s}</span>)}
            <span style={{background:backendStatus==="ok"?"#22c55e18":"#ff000018",border:`1px solid ${backendStatus==="ok"?"#22c55e33":"#ff444433"}`,color:backendStatus==="ok"?"#22c55e":"#ff6060",padding:"2px 7px",borderRadius:3,fontSize:"0.6rem",fontFamily:"monospace"}}>{backendStatus==="ok"?"● BACKEND":"○ BACKEND"}</span>
          </div>
          <div style={{color:"#38bdf8",fontFamily:"monospace",fontSize:"0.76rem",fontWeight:700}}>{time.toLocaleTimeString()}</div>
        </div>
      </div>

      {/* Nav + action bar */}
      <div style={{background:"#060d1a",borderBottom:"1px solid #0f172a",padding:"0 24px",display:"flex",alignItems:"center",gap:0}}>
        {/* Nav tabs */}
        <button onClick={()=>setNav("registry")} style={{background:"none",border:"none",borderBottom:nav==="registry"?"2px solid #38bdf8":"2px solid transparent",color:nav==="registry"?"#38bdf8":"#475569",padding:"10px 18px",cursor:"pointer",fontSize:"0.75rem",fontFamily:"monospace",fontWeight:nav==="registry"?700:400,transition:"all 0.15s",whiteSpace:"nowrap"}}>
          📋 DETECTION REGISTRY
        </button>
        <button onClick={()=>setNav("slack")} style={{background:"none",border:"none",borderBottom:nav==="slack"?"2px solid #f97316":"2px solid transparent",color:nav==="slack"?"#f97316":"#475569",padding:"10px 18px",cursor:"pointer",fontSize:"0.75rem",fontFamily:"monospace",fontWeight:nav==="slack"?700:400,transition:"all 0.15s",position:"relative",whiteSpace:"nowrap"}}>
          💬 SLACK ALERTS
          {critAlerts>0&&<span style={{position:"absolute",top:6,right:6,background:"#ff4444",color:"#fff",borderRadius:"50%",width:16,height:16,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"0.58rem",fontWeight:700}}>{critAlerts}</span>}
        </button>
        <button onClick={()=>setNav("agent")} style={{background:"none",border:"none",borderBottom:nav==="agent"?"2px solid #a855f7":"2px solid transparent",color:nav==="agent"?"#a855f7":"#475569",padding:"10px 18px",cursor:"pointer",fontSize:"0.75rem",fontFamily:"monospace",fontWeight:nav==="agent"?700:400,transition:"all 0.15s",position:"relative",whiteSpace:"nowrap"}}>
          🔬 AGENT INVESTIGATIONS
          {slackAlerts.filter(a=>!investigated.has(a.id)&&HIGH_PLUS.has(a.severity)).length>0&&<span style={{position:"absolute",top:6,right:6,background:"#a855f7",color:"#fff",borderRadius:"50%",width:16,height:16,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"0.58rem",fontWeight:700}}>{slackAlerts.filter(a=>!investigated.has(a.id)&&HIGH_PLUS.has(a.severity)).length}</span>}
        </button>
        <button onClick={()=>setNav("documents")} style={{background:"none",border:"none",borderBottom:nav==="documents"?"2px solid #22c55e":"2px solid transparent",color:nav==="documents"?"#22c55e":"#475569",padding:"10px 18px",cursor:"pointer",fontSize:"0.75rem",fontFamily:"monospace",fontWeight:nav==="documents"?700:400,transition:"all 0.15s",position:"relative",whiteSpace:"nowrap"}}>
          📁 DOCUMENTS
          {savedDocs.length>0&&<span style={{position:"absolute",top:6,right:6,background:"#22c55e",color:"#020817",borderRadius:"50%",width:16,height:16,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"0.58rem",fontWeight:700}}>{savedDocs.length}</span>}
        </button>
        <button onClick={()=>setNav("geointel")} style={{background:"none",border:"none",borderBottom:nav==="geointel"?"2px solid #0ea5e9":"2px solid transparent",color:nav==="geointel"?"#0ea5e9":"#475569",padding:"10px 18px",cursor:"pointer",fontSize:"0.75rem",fontFamily:"monospace",fontWeight:nav==="geointel"?700:400,transition:"all 0.15s",whiteSpace:"nowrap"}}>
          🌍 GEO INTEL
        </button>
        <button onClick={()=>setNav("tormon")} style={{background:"none",border:"none",borderBottom:nav==="tormon"?"2px solid #00ff8c":"2px solid transparent",color:nav==="tormon"?"#00ff8c":"#475569",padding:"10px 18px",cursor:"pointer",fontSize:"0.75rem",fontFamily:"monospace",fontWeight:nav==="tormon"?700:400,transition:"all 0.15s",whiteSpace:"nowrap"}}>
          ⬡ TOR MONITOR
        </button>
        <div style={{flex:1}}/>
        {nav==="registry"&&<>
          <input value={filter} onChange={e=>setFilter(e.target.value)} placeholder="Search rules..." style={{background:"#0a1628",border:"1px solid #1e293b",borderRadius:6,color:"#94a3b8",padding:"5px 12px",fontSize:"0.72rem",fontFamily:"monospace",outline:"none",width:280,marginRight:10}}/>
          <button onClick={()=>setModal("writer")} style={{background:"linear-gradient(135deg,#22c55e,#16a34a)",color:"#020817",border:"none",borderRadius:7,padding:"6px 14px",fontSize:"0.73rem",fontWeight:800,cursor:"pointer",fontFamily:"'Oxanium',monospace",letterSpacing:1,marginRight:8,whiteSpace:"nowrap"}}>✚ NEW RULE + IR</button>
        </>}
        <div style={{padding:"0 8px",display:"flex",gap:7,fontSize:"0.66rem",fontFamily:"monospace",color:"#475569"}}>
          {Object.entries(STATIC_REG).map(([k,g])=><span key={k} style={{color:g.color}}>{g.icon}{g.rules.length}</span>)}
          {customRules.length>0&&<span style={{color:"#22c55e"}}>📝{customRules.length}</span>}
          {liveCount>0&&<span style={{color:"#22d3ee"}}>📡{liveCount}</span>}
        </div>
      </div>

      {/* ── SLACK ALERTS VIEW ── */}
      {nav==="slack"&&<SlackHub alerts={slackAlerts} setAlerts={setSlackAlerts} onOpenFull={openAlertForInvestigation} onInvestigate={handleInvestigate} settings={settings} setSettings={setSettings} customRules={customRules} onSaveDoc={saveDoc}/>}

      {/* ── AGENT INVESTIGATIONS VIEW ── */}
      {nav==="agent"&&<InvestigationsTab alerts={slackAlerts} customRules={customRules} onInvestigate={handleInvestigate} investigated={investigated}/>}

      {/* ── DOCUMENTS VIEW ── */}
      {nav==="documents"&&<DocumentsTab docs={savedDocs} onDelete={deleteDoc}/>}

      {/* ── GEO INTEL VIEW ── */}
      {nav==="geointel"&&<GeoIntel />}

      {/* ── TOR MONITOR VIEW ── */}
      {nav==="tormon"&&<TorMonitor />}

      {/* ── REGISTRY VIEW ── */}
      {nav==="registry"&&(
        <div style={{padding:"14px 24px",display:"flex",flexDirection:"column",gap:10}}>
          {Object.entries(fullReg).map(([key,group])=>{
            const filt=filter?group.rules.filter(r=>r.name.toLowerCase().includes(fl)||r.file.toLowerCase().includes(fl)||r.tactic.toLowerCase().includes(fl)||r.mitre.toLowerCase().includes(fl)||r.id.toLowerCase().includes(fl)||(r.severity||"").toLowerCase().includes(fl)):group.rules;
            if(filter&&filt.length===0)return null;
            const isOpen=expanded.includes(key);
            return(
              <div key={key} style={{background:"#060d1a",border:`1px solid ${group.color}22`,borderRadius:10,overflow:"hidden"}}>
                <div onClick={()=>setExpanded(p=>p.includes(key)?p.filter(k=>k!==key):[...p,key])} style={{display:"flex",alignItems:"center",gap:10,padding:"10px 16px",cursor:"pointer",borderBottom:isOpen?`1px solid ${group.color}22`:"none",background:isOpen?group.color+"08":"transparent"}}>
                  <span style={{fontSize:"0.95rem"}}>{group.icon}</span>
                  <div style={{fontFamily:"'Oxanium',monospace",fontWeight:700,color:group.color,fontSize:"0.78rem",letterSpacing:1}}>{group.label}</div>
                  <span style={{background:group.color+"20",border:`1px solid ${group.color}44`,color:group.color,padding:"1px 7px",borderRadius:3,fontSize:"0.61rem",fontFamily:"monospace"}}>{filt.length} rules</span>
                  {group.isCustomGroup&&<><span style={{color:"#22c55e",fontSize:"0.61rem",fontFamily:"monospace"}}>● PERSISTED</span>{filt.filter(r=>r.playbook).length>0&&<span style={{color:"#f97316",fontSize:"0.61rem",fontFamily:"monospace"}}>🚨 {filt.filter(r=>r.playbook).length} with IR</span>}</>}
                  <span style={{marginLeft:"auto",color:"#334155",fontSize:"0.68rem"}}>{isOpen?"▲":"▼"}</span>
                </div>
                {isOpen&&<>
                  <div style={{display:"grid",gridTemplateColumns:"100px 1fr 145px 100px 100px",gap:10,padding:"5px 16px",background:"#0a1628",borderBottom:"1px solid #0f172a"}}>
                    {["RULE ID","DETECTION / FILE","TACTIC","MITRE","SEVERITY"].map((h,i)=><div key={i} style={{color:"#334155",fontSize:"0.61rem",fontFamily:"monospace",letterSpacing:1}}>{h}</div>)}
                  </div>
                  {filt.map(rule=><RuleRow key={rule.id} rule={rule} gc={group.color} onSelect={r=>setSelected({rule:r,liveAlert:null})} onDelete={rule.isCustom?handleDelete:null} customRules={customRules}/>)}
                </>}
              </div>
            );
          })}
        </div>
      )}

      {/* Footer */}
      <div style={{borderTop:"1px solid #0f172a",padding:"8px 24px",display:"flex",justifyContent:"space-between",color:"#1e293b",fontSize:"0.63rem",fontFamily:"monospace"}}>
        <div>SecurityOperations/rules/ · {totalAll} static + {liveCount} live detections · {customRules.length} custom · DET-YYYYMMDD-NNNN format</div>
        <div>MITRE ATT&CK v14 · IR: IR-YYYYMMDD-HHMMSS · OPXDR v4</div>
      </div>

      {/* Rule Writer Modal */}
      {modal==="writer"&&<RuleWriter onClose={()=>setModal(null)} onSave={handleSave}/>}
    </div>
  );
}
