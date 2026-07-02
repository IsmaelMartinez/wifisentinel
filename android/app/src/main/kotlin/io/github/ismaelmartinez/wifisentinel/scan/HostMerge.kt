package io.github.ismaelmartinez.wifisentinel.scan

/**
 * Pure host-list helpers used by [HostProbe]. Merge-by-IP and subnet
 * derivation are extracted here — free of any Android framework type — so they
 * can be unit-tested on the JVM without a device. See docs/android-companion.md §9.
 */
internal object HostMerge {
    /**
     * Merge hosts sharing an IP into one entry: the first non-null hostname /
     * serviceType wins, open ports are unioned and sorted. The result is
     * ordered by numeric IP so `.10` sorts after `.2`.
     */
    fun mergeByIp(hosts: List<LocalScanResult.Host>): List<LocalScanResult.Host> {
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

    /** The /24 prefix (`a.b.c`) of a dotted quad, or null when not 4 octets. */
    fun subnetBaseOf(ip: String): String? {
        val octets = ip.split(".")
        return if (octets.size == 4) octets.take(3).joinToString(".") else null
    }

    /** The final octet of a dotted quad, or null when absent / unparseable. */
    fun ownHostByte(ip: String?): Int? =
        ip?.split(".")?.getOrNull(3)?.toIntOrNull()

    /** Numeric key for sorting dotted-quad IPs; unparseable octets count as 0. */
    fun ipSortKey(ip: String): Long =
        ip.split(".").fold(0L) { acc, octet -> acc * 256 + (octet.toLongOrNull() ?: 0) }
}
