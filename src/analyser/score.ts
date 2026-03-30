import type { NetworkScanResult } from "../collector/schema/scan-result.js";

/** Compute an overall security score from 0 to 10. */
export function computeSecurityScore(result: NetworkScanResult): number {
  let score = 10;

  // Firewall
  if (!result.security.firewall.enabled) score -= 2;
  else if (!result.security.firewall.stealthMode) score -= 0.5;

  // VPN
  if (!result.security.vpn.active) score -= 1;

  // DNS
  if (result.network.dns.hijackTestResult === "intercepted") score -= 2;
  if (!result.network.dns.dnssecSupported) score -= 0.5;
  if (result.network.dns.anomalies.length > 0) score -= 0.5;

  // Intrusion indicators
  const ii = result.intrusionIndicators;
  if (ii) {
    const highArp = ii.arpAnomalies.filter(a => a.severity === "high").length;
    const highHost = ii.suspiciousHosts.filter(h => h.severity === "high").length;
    score -= highArp * 0.5;
    score -= highHost * 0.5;
    score -= ii.scanDetection.length * 0.3;
  }

  // Cameras
  if (result.hiddenDevices && result.hiddenDevices.suspectedCameras.length > 0) score -= 1;

  // Exposed services
  const exposed = result.localServices.filter(s => s.exposedToNetwork).length;
  score -= Math.min(exposed * 0.3, 1.5);

  // Kernel params
  if (result.security.kernelParams.ipForwarding) score -= 0.5;
  if (result.security.kernelParams.icmpRedirects) score -= 0.3;

  // Proxy
  if (result.security.proxy.enabled) score -= 0.5;

  // Traffic
  if (result.traffic) {
    score -= Math.min(result.traffic.unencrypted.length * 0.2, 1);
  }

  return Math.max(0, Math.min(10, Math.round(score * 10) / 10));
}
