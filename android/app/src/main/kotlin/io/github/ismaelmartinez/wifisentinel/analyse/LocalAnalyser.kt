package io.github.ismaelmartinez.wifisentinel.analyse

import io.github.ismaelmartinez.wifisentinel.scan.ChannelCongestion
import io.github.ismaelmartinez.wifisentinel.scan.LocalScanResult
import io.github.ismaelmartinez.wifisentinel.scan.LocalScanResult.Finding
import io.github.ismaelmartinez.wifisentinel.scan.LocalScanResult.Severity
import io.github.ismaelmartinez.wifisentinel.scan.SsidAnomalies

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
            addAll(wifiFindings(result.wifi, result.nearbyNetworks))
            addAll(vpnFindings(result.wifi, result.network))
            weakerTwinFinding(result.wifi, result.nearbyNetworks)?.let { add(it) }
            channelCongestionFinding(result.wifi, result.nearbyNetworks)?.let { add(it) }
            addAll(hostFindings(result.hosts))
            latencyFinding(result.latencyMs)?.let { add(it) }
        }.sortedBy { it.severity.ordinal }

        val overall = findings.minByOrNull { it.severity.ordinal }?.severity ?: Severity.INFO
        return LocalScanResult.Analysis(overallRisk = overall, findings = findings)
    }

    private fun wifiFindings(
        wifi: LocalScanResult.Wifi?,
        nearbyNetworks: List<LocalScanResult.NearbyNetwork>?,
    ): List<Finding> {
        if (wifi == null) {
            // Distinguish a deliberate nearby-only survey (no AP joined, but the
            // RF neighbourhood was captured) from a genuine failure to read the
            // connection. Both leave `wifi` null, but the honest message — and
            // the fix — differ: a survey is working as intended. "Captured" is a
            // non-null list per `LocalScanResult.nearbyNetworks` (null = not
            // collected); an empty-but-non-null list is still a survey that
            // simply saw no other APs, so key off nullness, not emptiness.
            val surveyed = nearbyNetworks != null
            return listOf(
                if (surveyed) {
                    Finding(
                        Severity.INFO,
                        "Nearby-only survey",
                        "No network was joined for this scan, so only the RF neighbourhood " +
                            "(${nearbyNetworks!!.size} nearby network(s)) was captured. Link " +
                            "security, VPN posture, and LAN checks need an associated network.",
                    )
                } else {
                    Finding(
                        Severity.INFO,
                        "WiFi state unavailable",
                        "Could not read the current WiFi connection. Grant the scan permission and try again.",
                    )
                },
            )
        }
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
            "ENHANCED OPEN" -> listOf(
                Finding(
                    Severity.LOW,
                    "Enhanced Open (OWE) network",
                    "Traffic is encrypted (OWE) but the network has no authentication — anyone can join. Fine for guest access; prefer WPA2/WPA3 for trusted use.",
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

    /**
     * MEDIUM-level finding when the connected SSID is also being advertised
     * nearby on weaker/open security than the joined link — the classic
     * evil-twin shape. Honest and phone-visible: it compares only the
     * connected link's security label with the labels `getScanResults()`
     * already surfaced, via [SsidAnomalies.weakerTwins].
     *
     * Skipped in survey mode (`wifi == null`): with no associated AP there is
     * no joined link to be a twin *of*, so no finding is fabricated.
     * False-positive guard: the same SSID on several BSSIDs with the *same*
     * security is ordinary mesh/roaming infrastructure and raises nothing —
     * only the security downgrade is the signal (the helper also refuses to
     * compare "unknown" labels rather than guess).
     *
     * Taxonomy cross-check: the CLI's `src/analyser/rf/rogue-ap.ts` rates the
     * same shape (same SSID, different BSSID, `isWeakerSecurity`) HIGH from
     * its richer vantage point. The phone stays at MEDIUM and says "possible":
     * its labels are coarse capability strings with no Personal/Enterprise
     * mode, and a legitimate dual-config AP (e.g. a guest radio misconfigured
     * onto the main SSID) looks identical from one passive scan — so the
     * finding flags the shape without over-claiming an attack.
     */
    private fun weakerTwinFinding(
        wifi: LocalScanResult.Wifi?,
        nearbyNetworks: List<LocalScanResult.NearbyNetwork>?,
    ): Finding? {
        if (wifi == null || nearbyNetworks.isNullOrEmpty()) return null
        val twins = SsidAnomalies.weakerTwins(
            connectedSsid = wifi.ssid,
            connectedSecurity = wifi.security,
            nearby = nearbyNetworks,
        )
        if (twins.isEmpty()) return null
        val suspects = twins.joinToString(", ") { twin ->
            "${twin.bssid} (${twin.security}, ${twin.band} ch ${twin.channel}, ${twin.signal} dBm)"
        }
        return Finding(
            Severity.MEDIUM,
            "Possible evil twin of this network",
            "\"${wifi.ssid}\" is also being advertised nearby with weaker security than " +
                "the ${wifi.security} link you are joined to: $suspects. This is the shape " +
                "of an evil-twin access point, but it can also be a misconfigured second " +
                "AP or guest radio on the same name. Avoid joining the weaker network and " +
                "verify your router's configuration.",
        )
    }

    /**
     * INFO-level nudge when the connected AP shares a congested 2.4 GHz channel
     * with the RF neighbourhood while a clearly-emptier non-overlapping channel
     * (1/6/11) exists. Honest and phone-visible: it reads only the connected
     * channel and the nearby-network list `getScanResults()` already surfaced.
     *
     * Skipped in survey mode: with no associated AP (`wifi == null`) there is no
     * channel to advise on, so no finding is fabricated. The
     * [ChannelCongestion.suggestLessCongestedChannel] helper also gates on the
     * 2.4 GHz band (5/6 GHz have ample non-overlapping channels, so overlap
     * congestion doesn't bite there) and on a real occupancy gap.
     */
    private fun channelCongestionFinding(
        wifi: LocalScanResult.Wifi?,
        nearbyNetworks: List<LocalScanResult.NearbyNetwork>?,
    ): Finding? {
        if (wifi == null || nearbyNetworks.isNullOrEmpty()) return null
        val suggestion = ChannelCongestion.suggestLessCongestedChannel(
            connectedChannel = wifi.channel,
            connectedBand = wifi.band,
            nearby = nearbyNetworks,
        ) ?: return null
        return Finding(
            Severity.INFO,
            "Congested 2.4 GHz channel",
            "This network's channel (${suggestion.connectedChannel}) overlaps " +
                "${networks(suggestion.connectedOccupancy)}, while channel " +
                "${suggestion.suggestedChannel} overlaps only ${suggestion.suggestedOccupancy}. " +
                "Retuning the router to channel ${suggestion.suggestedChannel} may reduce " +
                "interference — a suggestion only; the router's own channel picker may already " +
                "account for factors a phone can't see.",
        )
    }

    /** "1 nearby network" / "N nearby networks" — honest singular/plural. */
    private fun networks(count: Int): String =
        if (count == 1) "1 nearby network" else "$count nearby networks"

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
