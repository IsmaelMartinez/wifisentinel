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

    /** Drop empty and the redacted `02:00:...` BSSID. */
    fun normaliseBssid(raw: String?): String? =
        raw?.takeIf { it.isNotEmpty() && it != REDACTED_BSSID }

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
        freqMhz in 5170..5825 -> (freqMhz - 5000) / 5
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
}
