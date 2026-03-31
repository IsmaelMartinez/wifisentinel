import type { StoredScan } from "../store/types.js";
import { computeSecurityScore } from "../analyser/score.js";
import { analyseRF } from "../analyser/rf/index.js";

function esc(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function scoreColour(score: number): string {
  if (score >= 8) return "#22c55e";
  if (score >= 5) return "#eab308";
  return "#ef4444";
}

function severityColour(sev: string): string {
  switch (sev) {
    case "critical": return "#ef4444";
    case "high": return "#f97316";
    case "medium": return "#eab308";
    case "low": return "#3b82f6";
    default: return "#a1a1aa";
  }
}

function riskColour(risk: string): string {
  switch (risk) {
    case "critical": return "#ef4444";
    case "high": return "#f97316";
    case "medium": return "#eab308";
    case "low": return "#3b82f6";
    case "minimal": return "#22c55e";
    default: return "#a1a1aa";
  }
}

function statusIcon(status: string): string {
  switch (status) {
    case "pass": return "&#x2714;";
    case "fail": return "&#x2718;";
    case "partial": return "&#x25D0;";
    default: return "&#x2014;";
  }
}

function statusColour(status: string): string {
  switch (status) {
    case "pass": return "#22c55e";
    case "fail": return "#ef4444";
    case "partial": return "#eab308";
    default: return "#a1a1aa";
  }
}

function gradeColour(grade: string): string {
  switch (grade) {
    case "A": return "#22c55e";
    case "B": return "#86efac";
    case "C": return "#eab308";
    case "D": return "#f97316";
    default: return "#ef4444";
  }
}

function boolIcon(val: boolean | null | undefined, invert = false): string {
  if (val === null || val === undefined) return "Unknown";
  const good = invert ? !val : val;
  return good
    ? `<span style="color:#22c55e">&#x2714;</span>`
    : `<span style="color:#ef4444">&#x2718;</span>`;
}

export function renderHtmlReport(stored: StoredScan): string {
  const { scan, compliance, analysis } = stored;
  const rfAnalysis = stored.rfAnalysis ?? analyseRF(scan);
  const score = computeSecurityScore(scan);
  const colour = scoreColour(score);
  const pct = (score / 10) * 100;
  const ts = new Date(scan.meta.timestamp).toLocaleString();

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WiFi Sentinel Report — ${esc(scan.wifi.ssid ?? "(hidden)")} — ${scan.meta.timestamp.split("T")[0]}</title>
<style>
  :root{--bg:#0a0a0a;--fg:#fafafa;--card:#18181b;--border:#27272a;--muted:#a1a1aa;--green:#22c55e;--yellow:#eab308;--red:#ef4444}
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--fg);line-height:1.6;padding:2rem;max-width:1100px;margin:0 auto}
  h1{font-size:1.5rem;margin-bottom:.25rem}
  h2{font-size:1.2rem;margin:2rem 0 .75rem;border-bottom:1px solid var(--border);padding-bottom:.5rem}
  h3{font-size:1rem;margin:.75rem 0 .5rem}
  .card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem;margin-bottom:1rem}
  .meta{color:var(--muted);font-size:.85rem}
  .mono{font-family:"SF Mono",Menlo,monospace;font-size:.85rem}
  table{width:100%;border-collapse:collapse;font-size:.85rem;margin:.5rem 0}
  th,td{text-align:left;padding:.35rem .5rem;border-bottom:1px solid var(--border)}
  th{color:var(--muted);font-weight:600}
  .gauge{width:120px;height:120px;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto}
  .gauge-inner{width:90px;height:90px;border-radius:50%;background:var(--card);display:flex;align-items:center;justify-content:center;flex-direction:column}
  .gauge-score{font-size:1.8rem;font-weight:700;line-height:1}
  .gauge-label{font-size:.7rem;color:var(--muted)}
  .bar-bg{background:#27272a;border-radius:4px;height:8px;width:100%}
  .bar-fill{height:8px;border-radius:4px}
  .grid2{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
  .grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:1rem}
  .severity{font-weight:600;text-transform:uppercase;font-size:.75rem}
  .finding-item{margin-bottom:.75rem}
  .insight-block{margin-bottom:1rem;padding:.75rem;border-left:3px solid var(--border);background:rgba(255,255,255,.02)}

  @media print{
    :root{--bg:#fff;--fg:#111;--card:#f5f5f5;--border:#e0e0e0;--muted:#666}
    body{padding:1rem}
    .card{break-inside:avoid}
  }
</style>
</head>
<body>

<!-- Header -->
<h1>WiFi Sentinel — Network Security Report</h1>
<p class="meta">
  Scan ID: <span class="mono">${esc(scan.meta.scanId.slice(0, 8))}</span> &middot;
  ${esc(ts)} &middot;
  ${esc(scan.meta.hostname)} &middot;
  SSID: ${esc(scan.wifi.ssid ?? "(hidden)")} &middot;
  ${esc(scan.network.ip)}/${esc(scan.network.subnet)}
</p>

<!-- Security Score -->
<h2>Security Score</h2>
<div class="card" style="text-align:center">
  <div class="gauge" style="background:conic-gradient(${colour} 0% ${pct}%, #27272a ${pct}% 100%)">
    <div class="gauge-inner">
      <div class="gauge-score" style="color:${colour}">${score}</div>
      <div class="gauge-label">/ 10</div>
    </div>
  </div>
  <p style="margin-top:.5rem;color:${colour};font-weight:600">${score >= 8 ? "Good" : score >= 5 ? "Fair" : "Poor"}</p>
</div>

<!-- Network -->
<h2>Network</h2>
<div class="card">
  <h3>Gateway</h3>
  <p><span class="mono">${esc(scan.network.gateway.ip)}</span> — ${esc(scan.network.gateway.mac)}${scan.network.gateway.vendor ? ` (${esc(scan.network.gateway.vendor)})` : ""}</p>
  ${scan.network.topology.doubleNat ? `<p style="color:var(--yellow)">Double NAT detected</p>` : ""}

  <h3 style="margin-top:1rem">Hosts (${scan.network.hosts.length})</h3>
  <table>
    <tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Ports</th></tr>
    ${scan.network.hosts.map(h => `<tr>
      <td class="mono">${esc(h.ip)}</td>
      <td class="mono">${esc(h.mac)}</td>
      <td>${esc(h.vendor ?? "—")}</td>
      <td>${h.ports?.map(p => `${p.port}/${esc(p.service)}`).join(", ") ?? "—"}</td>
    </tr>`).join("")}
  </table>
</div>

<!-- WiFi -->
<h2>WiFi</h2>
<div class="card">
  <div class="grid2">
    <div>
      <p>Protocol: ${esc(scan.wifi.protocol)}</p>
      <p>Channel: ${scan.wifi.channel} (${esc(scan.wifi.band)}, ${esc(scan.wifi.width)})</p>
      <p>Security: ${esc(scan.wifi.security)}</p>
    </div>
    <div>
      <p>Signal: ${scan.wifi.signal} dBm / Noise: ${scan.wifi.noise} dBm</p>
      <p>SNR: ${scan.wifi.snr} dB</p>
      <p>TX Rate: ${scan.wifi.txRate} Mbps</p>
    </div>
  </div>

  ${scan.wifi.nearbyNetworks.length > 0 ? `
  <h3 style="margin-top:1rem">Nearby Networks (${scan.wifi.nearbyNetworks.length})</h3>
  <table>
    <tr><th>SSID</th><th>Security</th><th>Channel</th><th>Signal</th></tr>
    ${scan.wifi.nearbyNetworks.map(n => `<tr>
      <td>${esc(n.ssid ?? "(hidden)")}</td>
      <td>${esc(n.security)}</td>
      <td>${n.channel}</td>
      <td>${n.signal} dBm</td>
    </tr>`).join("")}
  </table>` : ""}
</div>

<!-- RF Intelligence -->
${rfAnalysis ? `
<h2>RF Intelligence</h2>
<div class="card">
  <h3>Channel Saturation</h3>
  <table>
    <tr><th>Ch</th><th>Band</th><th>Networks</th><th>Saturation</th><th></th></tr>
    ${rfAnalysis.channelMap.channels.map(ch => `<tr>
      <td>${ch.channel}${ch.channel === rfAnalysis.channelMap.currentChannel ? " ★" : ""}</td>
      <td>${esc(ch.band)}</td>
      <td>${ch.networkCount}</td>
      <td>${ch.saturationScore}%</td>
      <td><div class="bar-bg"><div class="bar-fill" style="width:${ch.saturationScore}%;background:${ch.saturationScore > 70 ? "var(--red)" : ch.saturationScore > 40 ? "var(--yellow)" : "var(--green)"}"></div></div></td>
    </tr>`).join("")}
  </table>

  <p style="margin-top:.75rem">Recommended channel: <strong>${rfAnalysis.channelMap.recommendedChannel}</strong> — ${esc(rfAnalysis.channelMap.recommendationReason)}</p>

  <h3 style="margin-top:1rem">Rogue AP Detection</h3>
  ${rfAnalysis.rogueAPs.findings.length === 0
    ? `<p style="color:var(--green)">No rogue APs detected.</p>`
    : rfAnalysis.rogueAPs.findings.map(f => `
      <div class="finding-item">
        <span class="severity" style="color:${severityColour(f.severity)}">[${esc(f.severity.toUpperCase())}]</span>
        ${esc(f.description)}
        ${f.ssid ? `<br><span class="meta">SSID: ${esc(f.ssid)} — Ch ${f.channel} — ${f.signal} dBm</span>` : ""}
      </div>`).join("")}
</div>` : ""}

<!-- Security Posture -->
<h2>Security Posture</h2>
<div class="card">
  <div class="grid2">
    <div>
      <p>Firewall: ${boolIcon(scan.security.firewall.enabled)} ${scan.security.firewall.enabled ? "Enabled" : "Disabled"}${scan.security.firewall.stealthMode ? " (stealth)" : ""}</p>
      <p>VPN: ${boolIcon(scan.security.vpn.active)} ${scan.security.vpn.active ? "Active" : "Inactive"}${scan.security.vpn.provider ? ` (${esc(scan.security.vpn.provider)})` : ""}</p>
      <p>Proxy: ${boolIcon(scan.security.proxy.enabled)} ${scan.security.proxy.enabled ? "Enabled" : "Disabled"}</p>
    </div>
    <div>
      <p>IP Forwarding: ${boolIcon(scan.security.kernelParams.ipForwarding, true)} ${scan.security.kernelParams.ipForwarding ? "Enabled" : "Disabled"}</p>
      <p>ICMP Redirects: ${boolIcon(scan.security.kernelParams.icmpRedirects, true)} ${scan.security.kernelParams.icmpRedirects ? "Enabled" : "Disabled"}</p>
      <p>Client Isolation: ${scan.security.clientIsolation === null ? "Unknown" : boolIcon(scan.security.clientIsolation)} ${scan.security.clientIsolation === true ? "Enabled" : scan.security.clientIsolation === false ? "Disabled" : ""}</p>
    </div>
  </div>
</div>

<!-- DNS Audit -->
<h2>DNS</h2>
<div class="card">
  <p>Servers: <span class="mono">${scan.network.dns.servers.map(s => esc(s)).join(", ")}</span></p>
  <p>DNSSEC: ${boolIcon(scan.network.dns.dnssecSupported)} ${scan.network.dns.dnssecSupported ? "Supported" : "Not supported"}</p>
  <p>DoH/DoT: ${boolIcon(scan.network.dns.dohDotEnabled)} ${scan.network.dns.dohDotEnabled ? "Enabled" : "Disabled"}</p>
  <p>Hijack Test: <span style="color:${scan.network.dns.hijackTestResult === "clean" ? "var(--green)" : scan.network.dns.hijackTestResult === "intercepted" ? "var(--red)" : "var(--muted)"}">${esc(scan.network.dns.hijackTestResult)}</span></p>
  ${scan.network.dns.anomalies.length > 0 ? `<p style="color:var(--yellow)">Anomalies: ${scan.network.dns.anomalies.map(a => esc(a)).join(", ")}</p>` : ""}
</div>

<!-- Connections -->
<h2>Connections</h2>
<div class="card">
  <div class="grid3">
    <div><p>Established: ${scan.connections.established}</p></div>
    <div><p>Listening: ${scan.connections.listening}</p></div>
    <div><p>TIME_WAIT: ${scan.connections.timeWait}</p></div>
  </div>
  ${scan.connections.topDestinations.length > 0 ? `
  <h3 style="margin-top:.75rem">Top Destinations</h3>
  <table>
    <tr><th>IP</th><th>Connections</th><th>Reverse DNS</th></tr>
    ${scan.connections.topDestinations.map(d => `<tr>
      <td class="mono">${esc(d.ip)}</td>
      <td>${d.count}</td>
      <td>${esc(d.reverseDns ?? "—")}</td>
    </tr>`).join("")}
  </table>` : ""}
</div>

<!-- Speed Test -->
${scan.speed ? `
<h2>Speed Test</h2>
<div class="card">
  <div class="grid2">
    <div>
      <p>Download: ${scan.speed.download.speedMbps} Mbps</p>
      <p>Upload: ${scan.speed.upload.speedMbps} Mbps</p>
      <p>Rating: ${esc(scan.speed.rating)}</p>
    </div>
    <div>
      <p>Latency: ${scan.speed.latency.internetMs} ms</p>
      <p>Jitter: ${scan.speed.jitter.internetMs} ms</p>
      <p>Packet Loss: ${scan.speed.packetLoss.internetPercent}%</p>
    </div>
  </div>
</div>` : ""}

<!-- Persona Analyses -->
<h2>Persona Analyses</h2>
<p class="meta" style="margin-bottom:.75rem">Consensus: <span style="color:${riskColour(analysis.consensusRating)};font-weight:600">${esc(analysis.consensusRating.toUpperCase())}</span></p>
${analysis.analyses.map(a => `
<div class="card">
  <h3>${esc(a.displayName)} — <span style="color:${riskColour(a.riskRating)}">${esc(a.riskRating.toUpperCase())}</span></h3>
  <p style="margin:.5rem 0">${esc(a.executiveSummary)}</p>
  ${a.insights.length > 0 ? `
  <h3 style="margin-top:.75rem">Insights</h3>
  ${a.insights.map(i => `
  <div class="insight-block" style="border-color:${severityColour(i.severity)}">
    <p><span class="severity" style="color:${severityColour(i.severity)}">${esc(i.severity.toUpperCase())}</span> — ${esc(i.title)}</p>
    <p class="meta" style="margin:.25rem 0">${esc(i.description)}</p>
    <p style="font-size:.85rem">Recommendation: ${esc(i.recommendation)}</p>
  </div>`).join("")}` : ""}
</div>`).join("")}

<!-- Compliance -->
<h2>Compliance</h2>
<div class="card" style="text-align:center;margin-bottom:1rem">
  <span style="font-size:2rem;font-weight:700;color:${gradeColour(compliance.overallGrade)}">${esc(compliance.overallGrade)}</span>
  <p class="meta">Overall Score: ${compliance.overallScore}%</p>
</div>
${compliance.standards.map(s => `
<div class="card">
  <div style="display:flex;justify-content:space-between;align-items:center">
    <h3>${esc(s.name)}</h3>
    <span style="font-size:1.2rem;font-weight:700;color:${gradeColour(s.grade)}">${esc(s.grade)}</span>
  </div>
  <div class="bar-bg" style="margin:.5rem 0">
    <div class="bar-fill" style="width:${s.score}%;background:${gradeColour(s.grade)}"></div>
  </div>
  <p class="meta">${s.score}% — ${esc(s.summary)}</p>
  ${s.findings.length > 0 ? `
  <table style="margin-top:.5rem">
    <tr><th></th><th>Finding</th><th>Severity</th><th>Status</th></tr>
    ${s.findings.map(f => `<tr>
      <td style="color:${statusColour(f.status)}">${statusIcon(f.status)}</td>
      <td>${esc(f.title)}</td>
      <td><span class="severity" style="color:${severityColour(f.severity)}">${esc(f.severity)}</span></td>
      <td>${esc(f.status)}</td>
    </tr>`).join("")}
  </table>` : ""}
</div>`).join("")}

<p class="meta" style="margin-top:2rem;text-align:center">Generated by WiFi Sentinel — ${esc(scan.meta.timestamp)}</p>
</body>
</html>`;
}
