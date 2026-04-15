package io.github.ismaelmartinez.wifisentinel.scan

import kotlinx.serialization.Serializable

/**
 * Narrower cousin of the CLI's `NetworkScanResult`. Field paths mirror the
 * Zod schema at `src/collector/schema/scan-result.ts` where the Android
 * runtime can populate them. Anything the phone cannot observe (traffic
 * capture, connections table, deauth detection, etc.) is omitted rather
 * than filled with zeros.
 *
 * The CLI side's future `import` command should validate this as a relaxed
 * variant of `NetworkScanResult` with `meta.platform = "android"` and
 * `meta.partial = true`.
 */
@Serializable
data class LocalScanResult(
    val meta: Meta,
    val wifi: Wifi?,
    val network: Network?,
    val hosts: List<Host> = emptyList(),
    val latencyMs: Long? = null,
) {
    @Serializable
    data class Meta(
        val scanId: String,
        val timestamp: String,
        val platform: String = "android",
        val partial: Boolean = true,
        val appVersion: String,
    )

    @Serializable
    data class Wifi(
        val ssid: String?,
        val bssid: String?,
        val security: String,
        val frequencyMhz: Int,
        val channel: Int,
        val rssi: Int,
        val linkSpeedMbps: Int,
        val macRandomised: Boolean?,
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
}
