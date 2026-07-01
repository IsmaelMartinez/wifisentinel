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
    val network: Network?,
    val hosts: List<Host> = emptyList(),
    val latencyMs: Long? = null,
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
     * `protocol`, `width`, `noise`, `snr`, `macRandomised`, `countryCode`,
     * `nearbyNetworks` (for now — will land with the host-discovery stage).
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
