package io.github.ismaelmartinez.wifisentinel.analyse

import io.github.ismaelmartinez.wifisentinel.scan.LocalScanResult
import io.github.ismaelmartinez.wifisentinel.scan.LocalScanResult.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for the rule-based [LocalAnalyser]. No Android framework
 * types are touched, so these run under `./gradlew test` without an emulator.
 */
class LocalAnalyserTest {

    private fun result(
        security: String = "WPA2",
        vpnActive: Boolean = false,
        hosts: List<LocalScanResult.Host> = emptyList(),
        latencyMs: Long? = null,
    ) = LocalScanResult(
        meta = LocalScanResult.Meta(
            scanId = "test",
            timestamp = "2026-07-01T00:00:00Z",
            appVersion = "test",
        ),
        wifi = LocalScanResult.Wifi(
            ssid = "Net",
            bssid = "aa:bb:cc:dd:ee:ff",
            security = security,
            channel = 36,
            band = "5 GHz",
            signal = -50,
            txRate = 866,
        ),
        network = LocalScanResult.Network(
            ip = "192.168.1.2",
            gatewayIp = "192.168.1.1",
            dnsServers = listOf("192.168.1.1"),
            vpnActive = vpnActive,
        ),
        hosts = hosts,
        latencyMs = latencyMs,
    )

    @Test
    fun openNetworkIsCritical() {
        val analysis = LocalAnalyser.analyse(result(security = "Open"))
        assertEquals(Severity.CRITICAL, analysis.overallRisk)
        assertTrue(analysis.findings.any { it.title.contains("Open", ignoreCase = true) })
    }

    @Test
    fun wepIsCritical() {
        assertEquals(Severity.CRITICAL, LocalAnalyser.analyse(result(security = "WEP")).overallRisk)
    }

    @Test
    fun legacyWpaIsHigh() {
        assertEquals(Severity.HIGH, LocalAnalyser.analyse(result(security = "WPA")).overallRisk)
    }

    @Test
    fun wpa3WithVpnIsInfoOnly() {
        val analysis = LocalAnalyser.analyse(result(security = "WPA3", vpnActive = true))
        assertEquals(Severity.INFO, analysis.overallRisk)
    }

    @Test
    fun openNetworkWithoutVpnRaisesVpnFinding() {
        val analysis = LocalAnalyser.analyse(result(security = "Open", vpnActive = false))
        assertTrue(analysis.findings.any { it.title.contains("VPN", ignoreCase = true) })
    }

    @Test
    fun activeVpnSuppressesVpnFinding() {
        val analysis = LocalAnalyser.analyse(result(security = "Open", vpnActive = true))
        assertTrue(analysis.findings.none { it.title.contains("VPN", ignoreCase = true) })
    }

    @Test
    fun cleartextServiceIsFlagged() {
        val hosts = listOf(LocalScanResult.Host(ip = "192.168.1.10", openPorts = listOf(80, 443)))
        val analysis = LocalAnalyser.analyse(result(security = "WPA2", hosts = hosts))
        assertTrue(analysis.findings.any { it.title.contains("Cleartext", ignoreCase = true) })
    }

    @Test
    fun encryptedOnlyHostRaisesNoCleartextFinding() {
        val hosts = listOf(LocalScanResult.Host(ip = "192.168.1.10", openPorts = listOf(443, 22)))
        val analysis = LocalAnalyser.analyse(result(security = "WPA2", hosts = hosts))
        assertTrue(analysis.findings.none { it.title.contains("Cleartext", ignoreCase = true) })
    }

    @Test
    fun highLatencyIsReportedAsInfo() {
        val analysis = LocalAnalyser.analyse(result(latencyMs = 500))
        assertTrue(analysis.findings.any { it.title.contains("latency", ignoreCase = true) })
    }

    @Test
    fun missingWifiReportsUnavailable() {
        val base = result()
        val analysis = LocalAnalyser.analyse(base.copy(wifi = null))
        assertTrue(analysis.findings.any { it.title.contains("unavailable", ignoreCase = true) })
    }

    @Test
    fun findingsAreSortedBySeverity() {
        val hosts = listOf(LocalScanResult.Host(ip = "192.168.1.10", openPorts = listOf(80)))
        val analysis = LocalAnalyser.analyse(result(security = "Open", hosts = hosts, latencyMs = 500))
        val ordinals = analysis.findings.map { it.severity.ordinal }
        assertEquals(ordinals.sorted(), ordinals)
    }
}
