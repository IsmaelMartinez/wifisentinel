package io.github.ismaelmartinez.wifisentinel.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Pure-JVM tests for [HostMerge], the merge-by-IP and subnet-derivation helpers
 * extracted from [HostProbe]. No Android framework types are touched, so these
 * run under `./gradlew test` without an emulator. See docs/android-companion.md §9.
 */
class HostMergeTest {

    private fun host(
        ip: String,
        hostname: String? = null,
        serviceType: String? = null,
        ports: List<Int> = emptyList(),
    ) = LocalScanResult.Host(ip = ip, hostname = hostname, serviceType = serviceType, openPorts = ports)

    @Test
    fun mergesEntriesSharingAnIp() {
        val merged = HostMerge.mergeByIp(
            listOf(
                host("192.168.1.10", hostname = "printer", ports = listOf(80, 631)),
                host("192.168.1.10", serviceType = "_ipp._tcp", ports = listOf(443, 80)),
            ),
        )
        assertEquals(1, merged.size)
        val host = merged.single()
        assertEquals("printer", host.hostname)
        assertEquals("_ipp._tcp", host.serviceType)
        // Ports unioned, de-duplicated, and sorted.
        assertEquals(listOf(80, 443, 631), host.openPorts)
    }

    @Test
    fun firstNonNullFieldWinsOnConflict() {
        val merged = HostMerge.mergeByIp(
            listOf(
                host("192.168.1.10", hostname = "first"),
                host("192.168.1.10", hostname = "second"),
            ),
        )
        assertEquals("first", merged.single().hostname)
    }

    @Test
    fun laterEntryFillsMissingField() {
        val merged = HostMerge.mergeByIp(
            listOf(
                host("192.168.1.10", hostname = null, ports = listOf(22)),
                host("192.168.1.10", hostname = "ssh-box"),
            ),
        )
        assertEquals("ssh-box", merged.single().hostname)
    }

    @Test
    fun sortsHostsByNumericIp() {
        val merged = HostMerge.mergeByIp(
            listOf(
                host("192.168.1.10"),
                host("192.168.1.2"),
                host("192.168.1.100"),
            ),
        )
        assertEquals(
            listOf("192.168.1.2", "192.168.1.10", "192.168.1.100"),
            merged.map { it.ip },
        )
    }

    @Test
    fun distinctIpsArePreserved() {
        val merged = HostMerge.mergeByIp(
            listOf(host("10.0.0.5", ports = listOf(80)), host("10.0.0.6", ports = listOf(443))),
        )
        assertEquals(2, merged.size)
    }

    // ---- subnet derivation ---------------------------------------------------

    @Test
    fun derivesSlash24Base() {
        assertEquals("192.168.1", HostMerge.subnetBaseOf("192.168.1.42"))
    }

    @Test
    fun subnetBaseIsNullForMalformedIp() {
        assertNull(HostMerge.subnetBaseOf("192.168.1"))
        assertNull(HostMerge.subnetBaseOf("not-an-ip"))
    }

    @Test
    fun extractsOwnHostByte() {
        assertEquals(42, HostMerge.ownHostByte("192.168.1.42"))
        assertNull(HostMerge.ownHostByte("192.168.1"))
        assertNull(HostMerge.ownHostByte(null))
    }

    @Test
    fun ipSortKeyOrdersNumerically() {
        val low = HostMerge.ipSortKey("192.168.1.2")
        val high = HostMerge.ipSortKey("192.168.1.10")
        assertEquals(true, low < high)
        assertEquals(0xC0A80102L, HostMerge.ipSortKey("192.168.1.2"))
    }
}
