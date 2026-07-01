package io.github.ismaelmartinez.wifisentinel.scan

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Build
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Lightweight host-discovery stage. It has no root, no raw sockets, and no ARP
 * table access, so it can only find hosts two ways:
 *
 *  1. **mDNS / DNS-SD** via [NsdManager] — devices that advertise a service
 *     (printers, Chromecasts, AirPlay targets, SSH boxes, …).
 *  2. **A bounded TCP connect sweep** of the local /24 on a handful of common
 *     ports.
 *
 * Both are best-effort: results are merged by IP, so a host found by both mDNS
 * and the sweep appears once with its service label and open ports combined.
 * There is no OS fingerprinting or nmap-grade detail — see
 * docs/android-companion.md §3.
 */
class HostProbe(private val context: Context) {

    /** Service types worth probing on a typical home / small-office LAN. */
    private val serviceTypes = listOf(
        "_http._tcp.",
        "_ipp._tcp.",
        "_airplay._tcp.",
        "_homekit._tcp.",
        "_ssh._tcp.",
        "_printer._tcp.",
        "_googlecast._tcp.",
    )

    /** Ports the TCP sweep checks. Kept short to bound wall-clock time. */
    private val sweepPorts = listOf(22, 53, 80, 443, 554, 8080, 8443)

    /**
     * Discover hosts on the network the device is attached to.
     *
     * @param localIp the phone's own IPv4 address (dotted quad), used to derive
     *   the /24 to sweep. When null or unparseable the TCP sweep is skipped and
     *   only mDNS results are returned.
     */
    suspend fun discover(localIp: String?): List<LocalScanResult.Host> =
        withContext(Dispatchers.IO) {
            val mdns = runCatching { discoverMdns() }.getOrDefault(emptyList())
            val swept = localIp?.let { subnetBaseOf(it) }
                ?.let { base -> runCatching { sweepTcp(base, ownHostByte(localIp)) }.getOrDefault(emptyList()) }
                ?: emptyList()
            mergeByIp(mdns + swept)
        }

    // ---- mDNS ----------------------------------------------------------------

    private suspend fun discoverMdns(
        perServiceTimeoutMs: Long = 3_000,
    ): List<LocalScanResult.Host> = coroutineScope {
        val nsd = context.getSystemService(Context.NSD_SERVICE) as? NsdManager
            ?: return@coroutineScope emptyList()

        serviceTypes.map { type ->
            async { discoverServiceType(nsd, type, perServiceTimeoutMs) }
        }.awaitAll().flatten()
    }

    private suspend fun discoverServiceType(
        nsd: NsdManager,
        serviceType: String,
        timeoutMs: Long,
    ): List<LocalScanResult.Host> {
        val found = mutableMapOf<String, LocalScanResult.Host>()

        val listener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(regType: String) {}
            override fun onDiscoveryStopped(serviceType: String) {}
            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {}
            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {}

            override fun onServiceFound(service: NsdServiceInfo) {
                resolve(nsd, service) { host ->
                    synchronized(found) { found[host.ip] = host }
                }
            }

            override fun onServiceLost(service: NsdServiceInfo) {}
        }

        return try {
            nsd.discoverServices(serviceType, NsdManager.PROTOCOL_DNS_SD, listener)
            withTimeoutOrNull(timeoutMs) {
                // NSD has no "discovery complete" signal, so we simply let it run
                // for the window and collect whatever resolves.
                while (true) kotlinx.coroutines.delay(100)
            }
            synchronized(found) { found.values.toList() }
        } finally {
            runCatching { nsd.stopServiceDiscovery(listener) }
        }
    }

    private fun resolve(
        nsd: NsdManager,
        service: NsdServiceInfo,
        onResolved: (LocalScanResult.Host) -> Unit,
    ) {
        val callback = object : NsdManager.ResolveListener {
            override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {}
            override fun onServiceResolved(serviceInfo: NsdServiceInfo) {
                val ip = hostAddressOf(serviceInfo) ?: return
                onResolved(
                    LocalScanResult.Host(
                        ip = ip,
                        hostname = serviceInfo.serviceName.takeIf { it.isNotBlank() },
                        serviceType = serviceInfo.serviceType?.trim('.')?.takeIf { it.isNotBlank() },
                        openPorts = listOfNotNull(serviceInfo.port.takeIf { it in 1..65_535 }),
                    ),
                )
            }
        }
        // resolveService is deprecated on API 34+ in favour of registerServiceInfoCallback,
        // but it remains the only path that works uniformly down to minSdk 29.
        @Suppress("DEPRECATION")
        runCatching { nsd.resolveService(service, callback) }
    }

    private fun hostAddressOf(info: NsdServiceInfo): String? {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            info.hostAddresses.firstNotNullOfOrNull { it.hostAddress }?.let { return it }
        }
        @Suppress("DEPRECATION")
        return info.host?.hostAddress
    }

    // ---- TCP connect sweep ---------------------------------------------------

    private suspend fun sweepTcp(
        subnetBase: String,
        ownHostByte: Int?,
        connectTimeoutMs: Int = 300,
        concurrency: Int = 32,
    ): List<LocalScanResult.Host> = coroutineScope {
        val gate = Semaphore(concurrency)
        val results = (1..254)
            .filter { it != ownHostByte }
            .map { hostByte ->
                val ip = "$subnetBase.$hostByte"
                async {
                    gate.withPermit {
                        val open = sweepPorts.filter { port -> isOpen(ip, port, connectTimeoutMs) }
                        if (open.isEmpty()) null
                        else LocalScanResult.Host(ip = ip, openPorts = open)
                    }
                }
            }
            .awaitAll()
        results.filterNotNull()
    }

    private fun isOpen(ip: String, port: Int, timeoutMs: Int): Boolean =
        Socket().use { socket ->
            runCatching {
                socket.connect(InetSocketAddress(ip, port), timeoutMs)
                true
            }.getOrDefault(false)
        }

    // ---- helpers -------------------------------------------------------------

    private fun mergeByIp(hosts: List<LocalScanResult.Host>): List<LocalScanResult.Host> {
        val byIp = LinkedHashMap<String, LocalScanResult.Host>()
        for (host in hosts) {
            val existing = byIp[host.ip]
            byIp[host.ip] = if (existing == null) {
                host
            } else {
                existing.copy(
                    hostname = existing.hostname ?: host.hostname,
                    serviceType = existing.serviceType ?: host.serviceType,
                    openPorts = (existing.openPorts + host.openPorts).distinct().sorted(),
                )
            }
        }
        return byIp.values.sortedBy { ipSortKey(it.ip) }
    }

    private fun subnetBaseOf(ip: String): String? {
        val octets = ip.split(".")
        return if (octets.size == 4) octets.take(3).joinToString(".") else null
    }

    private fun ownHostByte(ip: String?): Int? =
        ip?.split(".")?.getOrNull(3)?.toIntOrNull()

    private fun ipSortKey(ip: String): Long =
        ip.split(".").fold(0L) { acc, octet -> acc * 256 + (octet.toLongOrNull() ?: 0) }
}
