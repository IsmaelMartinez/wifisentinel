package io.github.ismaelmartinez.wifisentinel.scan

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.time.Instant
import java.util.UUID

/**
 * Orchestrates the on-device scan pipeline. Stages run sequentially for now
 * because most of them touch the same Wifi/Connectivity managers; move to a
 * structured-concurrency `coroutineScope { launch {} }` layout once the host
 * probe lands and the work can actually be parallelised.
 */
class LocalScanner(private val context: Context) {

    private val wifiManager: WifiManager =
        context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager

    private val connectivityManager: ConnectivityManager =
        context.applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    /**
     * Run the full scan pipeline. Must be called from a coroutine scope —
     * the work happens on `Dispatchers.IO`.
     */
    suspend fun scan(appVersion: String): LocalScanResult = withContext(Dispatchers.IO) {
        LocalScanResult(
            meta = LocalScanResult.Meta(
                scanId = UUID.randomUUID().toString(),
                timestamp = Instant.now().toString(),
                appVersion = appVersion,
            ),
            wifi = captureWifi(),
            network = captureNetwork(),
            // Host discovery, latency probe, and analyser are deliberately
            // unimplemented in the spike. See docs/android-companion.md §9.
            hosts = emptyList(),
            latencyMs = null,
        )
    }

    private fun captureWifi(): LocalScanResult.Wifi? {
        if (!hasScanPermission()) return null

        @Suppress("DEPRECATION")
        val info = wifiManager.connectionInfo ?: return null
        if (info.networkId == -1) return null

        val frequencyMhz = info.frequency
        return LocalScanResult.Wifi(
            ssid = info.ssid?.trim('"')?.takeIf { it.isNotEmpty() && it != "<unknown ssid>" },
            bssid = info.bssid?.takeIf { it.isNotEmpty() && it != "02:00:00:00:00:00" },
            // `WifiInfo` doesn't expose the security type directly — derive it
            // from the matching `ScanResult` when we have scan permission.
            security = deriveSecurity(info.bssid),
            frequencyMhz = frequencyMhz,
            channel = frequencyToChannel(frequencyMhz),
            rssi = info.rssi,
            linkSpeedMbps = info.linkSpeed,
            macRandomised = macRandomisedOrNull(info),
        )
    }

    private fun captureNetwork(): LocalScanResult.Network {
        @Suppress("DEPRECATION")
        val dhcp = wifiManager.dhcpInfo
        val activeNetwork = connectivityManager.activeNetwork
        val caps = activeNetwork?.let { connectivityManager.getNetworkCapabilities(it) }
        val linkProperties = activeNetwork?.let { connectivityManager.getLinkProperties(it) }

        val dnsServers = linkProperties
            ?.dnsServers
            ?.mapNotNull { it.hostAddress }
            ?: emptyList()

        return LocalScanResult.Network(
            ip = dhcp?.ipAddress?.takeIf { it != 0 }?.let(::formatIpv4),
            gatewayIp = dhcp?.gateway?.takeIf { it != 0 }?.let(::formatIpv4),
            dnsServers = dnsServers,
            vpnActive = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true,
        )
    }

    private fun deriveSecurity(bssid: String?): String {
        if (bssid == null || !hasScanPermission()) return "unknown"
        @Suppress("DEPRECATION")
        val results = runCatching { wifiManager.scanResults }.getOrElse { return "unknown" }
        val match = results.firstOrNull { it.BSSID.equals(bssid, ignoreCase = true) }
            ?: return "unknown"
        val capabilities = match.capabilities ?: return "unknown"
        return when {
            "WPA3" in capabilities -> "WPA3"
            "WPA2" in capabilities -> "WPA2"
            "WPA" in capabilities -> "WPA"
            "WEP" in capabilities -> "WEP"
            capabilities.contains("ESS") && !capabilities.contains("WPA") -> "Open"
            else -> "unknown"
        }
    }

    private fun hasScanPermission(): Boolean {
        val required = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            Manifest.permission.NEARBY_WIFI_DEVICES
        } else {
            Manifest.permission.ACCESS_FINE_LOCATION
        }
        return ContextCompat.checkSelfPermission(context, required) ==
            PackageManager.PERMISSION_GRANTED
    }

    private fun macRandomisedOrNull(info: android.net.wifi.WifiInfo): Boolean? {
        // `WifiInfo.macAddress` has been deprecated and mostly stubbed to
        // "02:00:00:00:00:00" since API 24; treat that sentinel as "yes,
        // randomised" and leave everything else ambiguous.
        @Suppress("DEPRECATION")
        val reported = info.macAddress ?: return null
        return reported == "02:00:00:00:00:00"
    }

    private fun formatIpv4(value: Int): String =
        "${value and 0xFF}.${(value shr 8) and 0xFF}.${(value shr 16) and 0xFF}.${(value shr 24) and 0xFF}"

    private fun frequencyToChannel(freqMhz: Int): Int = when {
        freqMhz == 2484 -> 14
        freqMhz in 2412..2472 -> (freqMhz - 2407) / 5
        freqMhz in 5170..5825 -> (freqMhz - 5000) / 5
        freqMhz in 5955..7115 -> (freqMhz - 5950) / 5 // 6 GHz / WiFi 6E
        else -> 0
    }
}
