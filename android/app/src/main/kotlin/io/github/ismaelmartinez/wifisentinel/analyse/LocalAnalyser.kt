package io.github.ismaelmartinez.wifisentinel.analyse

import io.github.ismaelmartinez.wifisentinel.scan.LocalScanResult
import io.github.ismaelmartinez.wifisentinel.scan.LocalScanResult.Finding
import io.github.ismaelmartinez.wifisentinel.scan.LocalScanResult.Severity

/**
 * Rule-based, on-device analyser. It implements the subset of the CLI's
 * persona/standards rules that are *honest* to evaluate from phone-visible
 * data — primarily WiFi link security, VPN posture, and plaintext services
 * reachable on the LAN. Anything that needs privileged access (traffic
 * inspection, ARP, monitor mode) is out of scope and deliberately not guessed
 * at, so results are flagged `partial = true`.
 *
 * Pure and dependency-free so it can be unit-tested on the JVM without an
 * Android device — see docs/android-companion.md §9.
 */
object LocalAnalyser {

    /** Cleartext protocols we can spot from the TCP sweep's open ports. */
    private val cleartextPorts = mapOf(
        21 to "FTP",
        23 to "Telnet",
        80 to "HTTP",
        8080 to "HTTP (alt)",
        554 to "RTSP",
    )

    fun analyse(result: LocalScanResult): LocalScanResult.Analysis {
        val findings = buildList {
            addAll(wifiFindings(result.wifi))
            addAll(vpnFindings(result.wifi, result.network))
            addAll(hostFindings(result.hosts))
            latencyFinding(result.latencyMs)?.let { add(it) }
        }.sortedBy { it.severity.ordinal }

        val overall = findings.minByOrNull { it.severity.ordinal }?.severity ?: Severity.INFO
        return LocalScanResult.Analysis(overallRisk = overall, findings = findings)
    }

    private fun wifiFindings(wifi: LocalScanResult.Wifi?): List<Finding> {
        if (wifi == null) return listOf(
            Finding(
                Severity.INFO,
                "WiFi state unavailable",
                "Could not read the current WiFi connection. Grant the scan permission and try again.",
            ),
        )
        return when (wifi.security.uppercase()) {
            "OPEN" -> listOf(
                Finding(
                    Severity.CRITICAL,
                    "Open (unencrypted) network",
                    "Traffic on this network is not encrypted at the WiFi layer and can be read by anyone nearby. Avoid sensitive activity or use a VPN.",
                ),
            )
            "WEP" -> listOf(
                Finding(
                    Severity.CRITICAL,
                    "WEP encryption is broken",
                    "WEP can be cracked in minutes with off-the-shelf tools. Treat this network as effectively open.",
                ),
            )
            "WPA" -> listOf(
                Finding(
                    Severity.HIGH,
                    "Legacy WPA encryption",
                    "WPA (TKIP) is deprecated and vulnerable. Prefer a network offering WPA2 or WPA3.",
                ),
            )
            "WPA2" -> listOf(
                Finding(
                    Severity.LOW,
                    "WPA2 in use",
                    "WPA2 is acceptable but WPA3 offers stronger protection (forward secrecy, protection against offline cracking) where available.",
                ),
            )
            "WPA3" -> listOf(
                Finding(
                    Severity.INFO,
                    "WPA3 in use",
                    "This network uses modern WPA3 encryption.",
                ),
            )
            else -> listOf(
                Finding(
                    Severity.INFO,
                    "WiFi security type unknown",
                    "Could not determine the encryption in use for this network.",
                ),
            )
        }
    }

    private fun vpnFindings(
        wifi: LocalScanResult.Wifi?,
        network: LocalScanResult.Network?,
    ): List<Finding> {
        val vpnActive = network?.vpnActive == true
        if (vpnActive) return emptyList()
        // Only warn when we positively know the link is insecure. When wifi is
        // null the security type is unknown (no permission / on cellular), so a
        // "no VPN on an insecure network" warning would be a false positive.
        val insecureLink = wifi?.security?.uppercase() in setOf("OPEN", "WEP")
        if (!insecureLink) return emptyList()
        return listOf(
            Finding(
                Severity.MEDIUM,
                "No VPN on an insecure network",
                "You are on a weakly-encrypted or open network with no active VPN. A VPN would protect your traffic from other users on this network.",
            ),
        )
    }

    private fun hostFindings(hosts: List<LocalScanResult.Host>): List<Finding> {
        val plaintext = hosts.flatMap { host ->
            host.openPorts.mapNotNull { port ->
                cleartextPorts[port]?.let { proto -> host to proto }
            }
        }
        if (plaintext.isEmpty()) return emptyList()
        val detail = plaintext.joinToString(", ") { (host, proto) ->
            "${host.hostname ?: host.ip} ($proto)"
        }
        return listOf(
            Finding(
                Severity.LOW,
                "Cleartext services on the LAN",
                "One or more devices expose services over unencrypted protocols: $detail. Anyone on this network can intercept those sessions.",
            ),
        )
    }

    private fun latencyFinding(latencyMs: Long?): Finding? {
        if (latencyMs == null || latencyMs <= HIGH_LATENCY_MS) return null
        return Finding(
            Severity.INFO,
            "High internet latency",
            "Round-trip latency to the internet was ${latencyMs} ms, which may make interactive traffic feel sluggish.",
        )
    }

    private const val HIGH_LATENCY_MS = 200L
}
