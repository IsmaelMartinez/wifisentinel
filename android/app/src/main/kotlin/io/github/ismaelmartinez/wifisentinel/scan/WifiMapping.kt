package io.github.ismaelmartinez.wifisentinel.scan

/**
 * Pure mapping helpers used by [LocalScanner] to turn raw Android WiFi /
 * network values into schema fields. They are extracted here — free of any
 * Android framework type — so the mapping logic can be unit-tested on the JVM
 * without a device or a fake `WifiManager`/`ConnectivityManager`. See
 * docs/android-companion.md §9.
 */
internal object WifiMapping {
    /** Sanitised BSSID returned to non-system callers when redacted. */
    private const val REDACTED_BSSID = "02:00:00:00:00:00"

    /** Placeholder SSID the platform returns when it can't disclose the name. */
    private const val UNKNOWN_SSID = "<unknown ssid>"

    /** Strip the quotes `WifiInfo` wraps SSIDs in; drop empty / placeholder. */
    fun normaliseSsid(raw: String?): String? =
        raw?.trim('"')?.takeIf { it.isNotEmpty() && it != UNKNOWN_SSID }

    /**
     * Lowercase (BSSIDs are case-insensitive hex; one canonical form keeps
     * history/trend comparisons trivial), drop empty and the redacted
     * `02:00:...` BSSID.
     */
    fun normaliseBssid(raw: String?): String? =
        raw?.lowercase()?.takeIf { it.isNotEmpty() && it != REDACTED_BSSID }

    /** Map a `ScanResult.capabilities` string to a coarse security label. */
    fun securityFromCapabilities(capabilities: String?): String {
        val caps = capabilities ?: return "unknown"
        return when {
            "WPA3" in caps -> "WPA3"
            "WPA2" in caps -> "WPA2"
            "WPA" in caps -> "WPA"
            "WEP" in caps -> "WEP"
            caps.contains("ESS") && !caps.contains("WPA") -> "Open"
            else -> "unknown"
        }
    }

    /**
     * Channel numbering reference: IEEE 802.11-2020 §17 for 2.4/5 GHz; the
     * 6 GHz case uses the WiFi 6E channel indexing where channel `n`
     * corresponds to `5950 + 5n` MHz (so channel 1 = 5955 MHz, channel 5 =
     * 5975 MHz, …).
     */
    fun frequencyToChannel(freqMhz: Int): Int = when {
        freqMhz == 2484 -> 14
        freqMhz in 2412..2472 -> (freqMhz - 2407) / 5
        // Upper bound 5895 includes UNII-4 (5845/5865/5885 MHz → channels
        // 169/173/177) — stopping at 5825 mapped real APs to the channel-0
        // "unknown" sentinel.
        freqMhz in 5170..5895 -> (freqMhz - 5000) / 5
        freqMhz in 5955..7115 -> (freqMhz - 5950) / 5
        else -> 0
    }

    fun frequencyToBand(freqMhz: Int): String = when {
        freqMhz in 2400..2500 -> "2.4 GHz"
        freqMhz in 5000..5900 -> "5 GHz"
        freqMhz in 5925..7125 -> "6 GHz"
        else -> "unknown"
    }

    /** Format a little-endian `DhcpInfo` IPv4 int as a dotted quad. */
    fun formatIpv4(value: Int): String =
        "${value and 0xFF}.${(value shr 8) and 0xFF}.${(value shr 16) and 0xFF}.${(value shr 24) and 0xFF}"

    /**
     * Keep the export bounded: a dense block of flats can surface 50+ APs,
     * and each entry costs JSON size on every export and Room row. 25 keeps
     * every network that could plausibly matter for congestion analysis.
     */
    const val NEARBY_NETWORKS_CAP = 25

    /**
     * Framework-free projection of the `ScanResult` fields the mapping needs,
     * so [mapNearbyNetworks] stays JVM-testable (same rationale as the rest
     * of this object).
     */
    data class RawNearbyNetwork(
        val ssid: String?,
        val bssid: String?,
        val capabilities: String?,
        val frequencyMhz: Int,
        val signalDbm: Int,
    )

    /**
     * Map raw scan results to the export's nearby-network list: normalise
     * SSIDs/BSSIDs, derive security/channel/band, exclude the connected AP,
     * dedupe by BSSID keeping the strongest sighting, sort strongest-first,
     * and cap at [cap]. Entries without a usable BSSID are dropped — they
     * can't be deduped or told apart from the connected AP. Dedupe happens
     * on the raw entries so sightings discarded by it are never fully mapped.
     */
    fun mapNearbyNetworks(
        raw: List<RawNearbyNetwork>,
        connectedBssid: String?,
        cap: Int = NEARBY_NETWORKS_CAP,
    ): List<LocalScanResult.NearbyNetwork> {
        // normaliseBssid lowercases, so plain equality is case-insensitive.
        val connected = connectedBssid?.lowercase()
        val strongestByBssid = LinkedHashMap<String, RawNearbyNetwork>()
        for (entry in raw) {
            val bssid = normaliseBssid(entry.bssid) ?: continue
            if (bssid == connected) continue
            val existing = strongestByBssid[bssid]
            if (existing == null || entry.signalDbm > existing.signalDbm) {
                strongestByBssid[bssid] = entry
            }
        }
        return strongestByBssid.entries
            .sortedByDescending { it.value.signalDbm }
            .take(cap)
            .map { (bssid, entry) ->
                LocalScanResult.NearbyNetwork(
                    ssid = normaliseSsid(entry.ssid),
                    bssid = bssid,
                    security = securityFromCapabilities(entry.capabilities),
                    channel = frequencyToChannel(entry.frequencyMhz),
                    band = frequencyToBand(entry.frequencyMhz),
                    signal = entry.signalDbm,
                )
            }
    }
}
