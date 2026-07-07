package io.github.ismaelmartinez.wifisentinel.scan

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.ScanResult
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.core.content.ContextCompat
import io.github.ismaelmartinez.wifisentinel.analyse.LocalAnalyser
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.time.Instant
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
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

    private val hostProbe = HostProbe(context.applicationContext)
    private val latencyProbe = LatencyProbe()
    private val speedProbe = SpeedProbe()

    /**
     * Run the scan pipeline. Must be called from a coroutine scope — the work
     * happens on `Dispatchers.IO`.
     *
     * @param includeSpeedTest run the opt-in download throughput probe
     *   (~25 MB of data — see [SpeedProbe]). Off by default. Ignored in
     *   [surveyOnly] mode.
     * @param surveyOnly run a nearby-only RF survey: skip the connected-AP
     *   capture (so `wifi` is null *by construction*, not because the read
     *   failed) and the LAN / internet probes (host discovery, latency, speed),
     *   which only mean anything against a joined network. The result carries
     *   just the RF neighbourhood — a useful scan while disconnected or with
     *   `WifiInfo` redacted, instead of an empty connected-AP card. See
     *   docs/android-companion.md §10.
     */
    suspend fun scan(
        appVersion: String,
        includeSpeedTest: Boolean = false,
        surveyOnly: Boolean = false,
    ): LocalScanResult = withContext(Dispatchers.IO) {
        // Kick off a fresh AP scan up front so `deriveSecurity` isn't reading
        // whatever stale cache the system last populated. The call is rate-
        // limited (4 per 2 min on API 28+); if it's denied or times out we
        // fall back to whatever's in cache.
        val freshScan = requestFreshScanResults()

        // Survey mode deliberately skips the connected-AP capture. Outside it,
        // the capture can still yield null on its own (the redacted API 31+
        // fallback — see §4); either way the nearby capture below is decoupled.
        val wifi = if (surveyOnly) null else captureWifi(freshScan)
        // Nearby capture is decoupled from the connected-AP capture: it only
        // needs the scan-result set and the (nullable) connected BSSID, so a
        // survey taken while disconnected — or with `WifiInfo` redacted, so
        // `wifi` is null — still exports the RF neighbourhood. When `wifi` is
        // null the connected BSSID is unknown, so nothing is excluded.
        val nearbyNetworks = captureNearbyNetworks(freshScan, wifi?.bssid)
        val network = captureNetwork()

        // The LAN / internet probes only produce meaningful data against a
        // joined network, so a survey skips them and stays a fast RF snapshot.
        val hosts: List<LocalScanResult.Host>
        val latencyMs: Long?
        val speed: LocalScanResult.Speed?
        if (surveyOnly) {
            hosts = emptyList()
            latencyMs = null
            speed = null
        } else {
            // Host discovery (mDNS + bounded TCP sweep) and the latency probe
            // are independent, so run them concurrently. Both are best-effort
            // and return empty/null on failure rather than aborting the scan.
            val hostsDeferred = async { hostProbe.discover(network.ip) }
            val latencyDeferred = async { latencyProbe.measure() }
            hosts = hostsDeferred.await()
            latencyMs = latencyDeferred.await()

            // Speed test runs last, after the latency probe has finished, so the
            // bulk download can't inflate the latency figure (the CLI orders its
            // stages the same way).
            speed = if (includeSpeedTest) speedProbe.measure() else null
        }

        val base = LocalScanResult(
            meta = LocalScanResult.Meta(
                scanId = UUID.randomUUID().toString(),
                timestamp = Instant.now().toString(),
                appVersion = appVersion,
            ),
            wifi = wifi,
            nearbyNetworks = nearbyNetworks,
            network = network,
            hosts = hosts,
            latencyMs = latencyMs,
            speed = speed,
        )

        base.copy(analysis = LocalAnalyser.analyse(base))
    }

    private suspend fun captureWifi(scanResults: List<ScanResult>): LocalScanResult.Wifi? {
        if (!hasScanPermission()) return null

        val info = currentWifiInfo() ?: return null

        val bssid = WifiMapping.normaliseBssid(info.bssid)
        val ssid = WifiMapping.normaliseSsid(info.ssid)
        // On API 31+ the location-aware callback is the only route to an
        // unredacted `WifiInfo`; when it times out we fall back to the
        // synchronous snapshot, which stays redacted — SSID `<unknown ssid>`,
        // BSSID `02:00:00:00:00:00`, both normalising to null. Without an
        // identity the section is signal-only: it can't be security-scored (no
        // BSSID to match against the scan results, so `security` is "unknown"),
        // correlated across scans (the import folds a null BSSID to the
        // "unknown" sentinel), or told apart from an entry in the nearby list.
        // Drop it rather than emit a misleading connected-AP finding — the RF
        // neighbourhood is captured independently now (see the top-level
        // `nearbyNetworks` field and docs/android-companion.md §10).
        if (bssid == null && ssid == null) return null

        val frequencyMhz = info.frequency
        return LocalScanResult.Wifi(
            ssid = ssid,
            bssid = bssid,
            // `WifiInfo` doesn't expose the security type directly — derive it
            // from the matching entry in the scan result set.
            security = deriveSecurity(bssid, scanResults),
            channel = WifiMapping.frequencyToChannel(frequencyMhz),
            band = WifiMapping.frequencyToBand(frequencyMhz),
            signal = info.rssi,
            txRate = info.linkSpeed,
        )
    }

    /**
     * Map the fresh scan-result set into the export's nearby-network list.
     * Decoupled from [captureWifi] so a survey taken while disconnected — or
     * with the connected `WifiInfo` redacted — still exports the RF
     * neighbourhood ([WifiMapping.mapNearbyNetworks] already takes a nullable
     * `connectedBssid`, so a null connected AP simply excludes nothing).
     *
     * Returns null when nothing could be collected (no scan permission), so
     * "not collected" stays distinguishable from a genuine "none seen" (an
     * empty list). The connected AP, when known, is excluded so it isn't
     * double-counted between [captureWifi] and this list.
     */
    private fun captureNearbyNetworks(
        scanResults: List<ScanResult>,
        connectedBssid: String?,
    ): List<LocalScanResult.NearbyNetwork>? {
        if (!hasScanPermission()) return null
        return WifiMapping.mapNearbyNetworks(
            raw = scanResults.map { scan ->
                // `ScanResult.SSID` is deprecated on API 33+ in favour of
                // `wifiSsid`, but the replacement needs a UTF-8 decode dance
                // and minSdk is 29 — the deprecated field is fine for a
                // display string.
                @Suppress("DEPRECATION")
                val rawSsid = scan.SSID
                WifiMapping.RawNearbyNetwork(
                    ssid = rawSsid,
                    bssid = scan.BSSID,
                    capabilities = scan.capabilities,
                    frequencyMhz = scan.frequency,
                    signalDbm = scan.level,
                )
            },
            connectedBssid = connectedBssid,
        )
    }

    /**
     * On API 31+ a `WifiInfo` obtained from the synchronous
     * `getNetworkCapabilities()` snapshot is location-redacted for all
     * non-system callers, no matter which permissions are held: SSID reads
     * `<unknown ssid>`, BSSID reads `02:00:00:00:00:00`, and `networkId`
     * reads -1. The only supported route to an unredacted copy is a
     * `NetworkCallback` registered with `FLAG_INCLUDE_LOCATION_INFO`, so try
     * that first and keep the synchronous snapshot (fine on API 29/30) and
     * the deprecated `getConnectionInfo()` getter as fallbacks.
     */
    private suspend fun currentWifiInfo(): WifiInfo? {
        // Only pay for the location-aware callback (and its timeout) when there
        // is actually a WiFi network to read — otherwise a scan on cellular
        // would block for the full timeout before falling through to null.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && isWifiAvailable()) {
            wifiInfoViaLocationAwareCallback()?.let { return it }
        }
        // `transportInfo` is only a `WifiInfo` when the active network is
        // actually WiFi, so the cast itself is the connection test — it's null
        // on cellular and on a VPN network (whose caps carry TRANSPORT_VPN, not
        // WIFI), and we fall through to the deprecated getter for those.
        val active = connectivityManager.activeNetwork
        val caps = active?.let { connectivityManager.getNetworkCapabilities(it) }
        (caps?.transportInfo as? WifiInfo)?.let { return it }
        @Suppress("DEPRECATION")
        val legacy = wifiManager.connectionInfo
        // The legacy getter returns a non-null shell even when disconnected;
        // networkId -1 is its "not connected" signal (valid on API < 31; on
        // API 31+ it is redacted to -1, so this deep fallback yields no WiFi
        // section there — the callback above is the real API 31+ path).
        return legacy?.takeIf { it.networkId != -1 }
    }

    /**
     * True when any network currently carries the WiFi transport — the active
     * one, or (when a VPN is up) the underlying WiFi network, which is why we
     * scan `allNetworks` rather than only `activeNetwork`. Lets [currentWifiInfo]
     * skip the location-aware callback when there is no WiFi to read.
     */
    private fun isWifiAvailable(): Boolean {
        val active = connectivityManager.activeNetwork
        val activeCaps = active?.let { connectivityManager.getNetworkCapabilities(it) }
        if (activeCaps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true) return true
        @Suppress("DEPRECATION")
        return connectivityManager.allNetworks.any { net ->
            connectivityManager.getNetworkCapabilities(net)
                ?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
        }
    }

    /**
     * Fetch the current `WifiInfo` through a location-aware
     * `NetworkCallback`. Registration immediately replays the capabilities
     * of any network already satisfying the request, so when the device is
     * on WiFi this resumes almost instantly; when it isn't, the timeout
     * expires and the caller falls back. Note the unredacted fields still
     * require the runtime scan permission ([hasScanPermission] gates the
     * whole capture) — without it the platform just leaves them redacted.
     */
    @RequiresApi(Build.VERSION_CODES.S)
    private suspend fun wifiInfoViaLocationAwareCallback(
        timeoutMs: Long = 3_000,
    ): WifiInfo? = withTimeoutOrNull(timeoutMs) {
        suspendCancellableCoroutine { cont ->
            // Same double-resume hazard as requestFreshScanResults: the
            // callback fires on the ConnectivityManager thread while the
            // registration-failure branch runs on the caller's thread.
            val resumed = AtomicBoolean(false)

            val callback = object : ConnectivityManager.NetworkCallback(
                ConnectivityManager.NetworkCallback.FLAG_INCLUDE_LOCATION_INFO,
            ) {
                override fun onCapabilitiesChanged(
                    network: Network,
                    capabilities: NetworkCapabilities,
                ) {
                    val info = capabilities.transportInfo as? WifiInfo ?: return
                    if (resumed.compareAndSet(false, true)) {
                        runCatching { connectivityManager.unregisterNetworkCallback(this) }
                        if (cont.isActive) cont.resume(info)
                    }
                }
            }

            cont.invokeOnCancellation {
                // Timeout or caller cancellation — just tear down; the
                // continuation is already dead so there is nothing to resume.
                if (resumed.compareAndSet(false, true)) {
                    runCatching { connectivityManager.unregisterNetworkCallback(callback) }
                }
            }

            val request = NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                .build()
            try {
                connectivityManager.registerNetworkCallback(request, callback)
            } catch (_: RuntimeException) {
                // Registration can fail if the process has hit the callback
                // limit — degrade to the synchronous fallback path.
                if (resumed.compareAndSet(false, true) && cont.isActive) {
                    cont.resume(null)
                }
            }
        }
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
            ip = dhcp?.ipAddress?.takeIf { it != 0 }?.let(WifiMapping::formatIpv4),
            gatewayIp = dhcp?.gateway?.takeIf { it != 0 }?.let(WifiMapping::formatIpv4),
            dnsServers = dnsServers,
            vpnActive = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true,
        )
    }

    private fun deriveSecurity(bssid: String?, scanResults: List<ScanResult>): String {
        if (bssid == null) return "unknown"
        val match = scanResults.firstOrNull { it.BSSID.equals(bssid, ignoreCase = true) }
            ?: return "unknown"
        return WifiMapping.securityFromCapabilities(match.capabilities)
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
                // Two code paths can race to resume the continuation: the
                // broadcast receiver (main thread) and the `startScan()`
                // failure branch (IO thread). Without this CAS guard, a
                // broadcast from a prior in-flight scan landing just as
                // `startScan()` returns false could trigger a double-resume
                // and crash with `IllegalStateException("Already resumed")`.
                val resumed = AtomicBoolean(false)

                fun unregister(receiver: BroadcastReceiver) {
                    try {
                        context.unregisterReceiver(receiver)
                    } catch (_: IllegalArgumentException) {
                        // Already unregistered — safe to ignore.
                    }
                }

                fun resumeOnce(value: List<ScanResult>) {
                    if (resumed.compareAndSet(false, true) && cont.isActive) {
                        cont.resume(value)
                    }
                }

                val receiver = object : BroadcastReceiver() {
                    override fun onReceive(ctx: Context, intent: Intent) {
                        unregister(this)
                        resumeOnce(readCachedScanResults())
                    }
                }

                ContextCompat.registerReceiver(
                    context,
                    receiver,
                    IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION),
                    ContextCompat.RECEIVER_NOT_EXPORTED,
                )

                cont.invokeOnCancellation { unregister(receiver) }

                @Suppress("DEPRECATION")
                val started = try {
                    wifiManager.startScan()
                } catch (_: SecurityException) {
                    false
                }
                if (!started) {
                    // Throttled or denied — resume with whatever is cached so
                    // the caller isn't blocked for the full timeout.
                    unregister(receiver)
                    resumeOnce(readCachedScanResults())
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
}
