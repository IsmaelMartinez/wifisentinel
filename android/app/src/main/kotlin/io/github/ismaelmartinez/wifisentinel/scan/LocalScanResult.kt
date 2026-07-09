package io.github.ismaelmartinez.wifisentinel.scan

import kotlinx.serialization.Serializable

/**
 * Narrower cousin of the CLI's `NetworkScanResult`. Field names mirror the
 * Zod schema at `src/collector/schema/scan-result.ts` so the planned
 * `wifisentinel import <file>` command can validate against a relaxed
 * variant without renaming. Anything the phone cannot observe (traffic
 * capture, connections table, deauth detection, MAC randomisation state,
 * etc.) is omitted rather than filled with zeros.
 *
 * `meta.platform = "android"` and `meta.partial = true` flag to the import
 * path that it should not expect the full CLI shape.
 */
@Serializable
data class LocalScanResult(
    val meta: Meta,
    val wifi: Wifi?,
    /**
     * The RF neighbourhood observed by `WifiManager.getScanResults()`, deduped
     * by BSSID and excluding the connected AP (see [WifiMapping.mapNearbyNetworks]).
     * Feeds the CLI's `wifi.nearbyNetworks` on import so channel-congestion and
     * rogue-AP analysis work on imported scans.
     *
     * Deliberately a top-level field rather than nested under [wifi]: nearby
     * capture only needs the scan-result set and the (nullable) connected BSSID,
     * so a survey taken while disconnected — or with `WifiInfo` redacted, so
     * [wifi] is null — still exports the RF environment. See
     * docs/android-companion.md §10.
     *
     * Null (never empty-defaulted) when nothing was collected — no scan
     * permission, or a Room record from an app version that predates the field.
     * The scanner sets a (possibly empty) list whenever the scan permission is
     * held, so "not collected" stays distinguishable from "none seen".
     */
    val nearbyNetworks: List<NearbyNetwork>? = null,
    val network: Network?,
    val hosts: List<Host> = emptyList(),
    val latencyMs: Long? = null,
    /**
     * Opt-in download speed test result. Null when the user left the toggle
     * off or the probe failed — never zero-filled.
     */
    val speed: Speed? = null,
    /**
     * Rule-based on-device analysis. Omitted from the JSON export's contract
     * with the CLI import path (which recomputes analysis from the raw fields),
     * but useful for the phone UI. Null until the analyse stage has run.
     */
    val analysis: Analysis? = null,
) {
    @Serializable
    data class Meta(
        val scanId: String,
        val timestamp: String,
        val platform: String = "android",
        val partial: Boolean = true,
        val appVersion: String,
    )

    /**
     * Field names chosen to align with the CLI's `wifi` shape: `signal`
     * (dBm), `txRate` (Mbps), `band` (human string). `channel` is the
     * 802.11 channel number, same semantics as the CLI.
     *
     * Deliberately omitted (not observable from an unprivileged Android app):
     * `protocol`, `width`, `noise`, `snr`, `macRandomised`, `countryCode`.
     */
    @Serializable
    data class Wifi(
        val ssid: String?,
        val bssid: String?,
        val security: String,
        val channel: Int,
        val band: String,
        val signal: Int,
        val txRate: Int,
    ) {
        /**
         * The connected AP as a nearby-shaped entry, or null when the BSSID
         * is redacted. [WifiMapping.mapNearbyNetworks] excludes the connected
         * BSSID from the nearby list, so consumers comparing whole
         * neighbourhoods ([SsidAnomalies], [RfDiff]) fold the AP back in via
         * this shape; a null BSSID could not have been excluded from the
         * list, so folding it back could double-count the same radio.
         */
        fun asNearbyNetwork(): NearbyNetwork? = bssid?.let {
            NearbyNetwork(
                ssid = ssid,
                bssid = it,
                security = security,
                channel = channel,
                band = band,
                signal = signal,
            )
        }
    }

    /**
     * A nearby AP from the scan results. `band` is phone-side colour for the
     * UI/export; the CLI's `NearbyNetwork` shape has no band field and its
     * import drops it. `ssid` is null for hidden networks.
     */
    @Serializable
    data class NearbyNetwork(
        val ssid: String?,
        val bssid: String,
        val security: String,
        val channel: Int,
        val band: String,
        val signal: Int,
    )

    @Serializable
    data class Network(
        val ip: String?,
        val gatewayIp: String?,
        val dnsServers: List<String> = emptyList(),
        val vpnActive: Boolean,
    )

    @Serializable
    data class Host(
        val ip: String,
        val hostname: String? = null,
        val serviceType: String? = null,
        val openPorts: List<Int> = emptyList(),
    )

    /**
     * Download-only subset of the CLI's `speed` section. The CLI shape also
     * carries upload, jitter, and packet-loss measurements the phone doesn't
     * take, so only the `download` object (whose field names match exactly)
     * is present here.
     */
    @Serializable
    data class Speed(
        val download: Download,
    ) {
        @Serializable
        data class Download(
            val speedMbps: Double,
            val bytesTransferred: Long,
            val durationMs: Long,
            val testUrl: String,
        )
    }

    /**
     * Result of the rule-based [io.github.ismaelmartinez.wifisentinel.analyse.LocalAnalyser].
     * `partial` mirrors `meta.partial`: this is an honest subset of the CLI's
     * multi-persona analysis, evaluated only from phone-visible fields.
     */
    @Serializable
    data class Analysis(
        val overallRisk: Severity,
        val findings: List<Finding>,
        val partial: Boolean = true,
    )

    @Serializable
    data class Finding(
        val severity: Severity,
        val title: String,
        val detail: String,
    )

    /** Ordered most to least severe; [ordinal] gives the ranking. */
    @Serializable
    enum class Severity { CRITICAL, HIGH, MEDIUM, LOW, INFO }
}
