package io.github.ismaelmartinez.wifisentinel.scan

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.ScanResult
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.time.Instant
import java.util.UUID
import kotlin.coroutines.resume

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
        // Kick off a fresh AP scan up front so `deriveSecurity` isn't reading
        // whatever stale cache the system last populated. The call is rate-
        // limited (4 per 2 min on API 28+); if it's denied or times out we
        // fall back to whatever's in cache.
        val freshScan = requestFreshScanResults()

        LocalScanResult(
            meta = LocalScanResult.Meta(
                scanId = UUID.randomUUID().toString(),
                timestamp = Instant.now().toString(),
                appVersion = appVersion,
            ),
            wifi = captureWifi(freshScan),
            network = captureNetwork(),
            // Host discovery, latency probe, and analyser are deliberately
            // unimplemented in the spike. See docs/android-companion.md §9.
            hosts = emptyList(),
            latencyMs = null,
        )
    }

    private fun captureWifi(scanResults: List<ScanResult>): LocalScanResult.Wifi? {
        if (!hasScanPermission()) return null

        val info = currentWifiInfo() ?: return null
        if (info.networkId == -1) return null

        val frequencyMhz = info.frequency
        val bssid = info.bssid?.takeIf { it.isNotEmpty() && it != "02:00:00:00:00:00" }
        return LocalScanResult.Wifi(
            ssid = info.ssid?.trim('"')?.takeIf { it.isNotEmpty() && it != "<unknown ssid>" },
            bssid = bssid,
            // `WifiInfo` doesn't expose the security type directly — derive it
            // from the matching entry in the scan result set.
            security = deriveSecurity(bssid, scanResults),
            channel = frequencyToChannel(frequencyMhz),
            band = frequencyToBand(frequencyMhz),
            signal = info.rssi,
            txRate = info.linkSpeed,
        )
    }

    /**
     * On API 31+ the `WifiManager.getConnectionInfo()` path returns a
     * redacted `WifiInfo` to non-system callers; the supported route is
     * `NetworkCapabilities.getTransportInfo()`. `getTransportInfo()` exists
     * since API 29, so we use it uniformly and only fall back to the
     * deprecated getter if there is no active network.
     */
    private fun currentWifiInfo(): WifiInfo? {
        val active = connectivityManager.activeNetwork
        val caps = active?.let { connectivityManager.getNetworkCapabilities(it) }
        (caps?.transportInfo as? WifiInfo)?.let { return it }
        @Suppress("DEPRECATION")
        return wifiManager.connectionInfo
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

    private fun deriveSecurity(bssid: String?, scanResults: List<ScanResult>): String {
        if (bssid == null) return "unknown"
        val match = scanResults.firstOrNull { it.BSSID.equals(bssid, ignoreCase = true) }
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

    /**
     * Request a fresh WiFi scan and suspend until the system broadcasts that
     * new results are available. Returns the cached results if the scan is
     * throttled, denied, or doesn't complete within [timeoutMs].
     */
    private suspend fun requestFreshScanResults(
        timeoutMs: Long = 5_000,
    ): List<ScanResult> {
        if (!hasScanPermission()) return emptyList()

        return withTimeoutOrNull(timeoutMs) {
            suspendCancellableCoroutine<List<ScanResult>> { cont ->
                val receiver = object : BroadcastReceiver() {
                    override fun onReceive(ctx: Context, intent: Intent) {
                        try {
                            context.unregisterReceiver(this)
                        } catch (_: IllegalArgumentException) {
                            // Already unregistered — safe to ignore.
                        }
                        if (cont.isActive) cont.resume(readCachedScanResults())
                    }
                }

                ContextCompat.registerReceiver(
                    context,
                    receiver,
                    IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION),
                    ContextCompat.RECEIVER_NOT_EXPORTED,
                )

                cont.invokeOnCancellation {
                    try {
                        context.unregisterReceiver(receiver)
                    } catch (_: IllegalArgumentException) {
                        // Already unregistered.
                    }
                }

                @Suppress("DEPRECATION")
                val started = try {
                    wifiManager.startScan()
                } catch (_: SecurityException) {
                    false
                }
                if (!started) {
                    // Throttled or denied — resume with whatever is cached so
                    // the caller isn't blocked for the full timeout.
                    try {
                        context.unregisterReceiver(receiver)
                    } catch (_: IllegalArgumentException) {
                        // Already unregistered.
                    }
                    if (cont.isActive) cont.resume(readCachedScanResults())
                }
            }
        } ?: readCachedScanResults()
    }

    private fun readCachedScanResults(): List<ScanResult> {
        return try {
            @Suppress("DEPRECATION")
            wifiManager.scanResults ?: emptyList()
        } catch (_: SecurityException) {
            emptyList()
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

    private fun formatIpv4(value: Int): String =
        "${value and 0xFF}.${(value shr 8) and 0xFF}.${(value shr 16) and 0xFF}.${(value shr 24) and 0xFF}"

    /**
     * Channel numbering reference: IEEE 802.11-2020 §17 for 2.4/5 GHz; the
     * 6 GHz case uses the WiFi 6E channel indexing where channel `n`
     * corresponds to `5950 + 5n` MHz (so channel 1 = 5955 MHz, channel 5 =
     * 5975 MHz, …).
     */
    private fun frequencyToChannel(freqMhz: Int): Int = when {
        freqMhz == 2484 -> 14
        freqMhz in 2412..2472 -> (freqMhz - 2407) / 5
        freqMhz in 5170..5825 -> (freqMhz - 5000) / 5
        freqMhz in 5955..7115 -> (freqMhz - 5950) / 5
        else -> 0
    }

    private fun frequencyToBand(freqMhz: Int): String = when {
        freqMhz in 2400..2500 -> "2.4 GHz"
        freqMhz in 5000..5900 -> "5 GHz"
        freqMhz in 5925..7125 -> "6 GHz"
        else -> "unknown"
    }
}
