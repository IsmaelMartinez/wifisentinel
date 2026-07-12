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
        nearbyNetworks: List<LocalScanResult.NearbyNetwork>? = null,
        channel: Int = 36,
        band: String = "5 GHz",
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
            channel = channel,
            band = band,
            signal = -50,
            txRate = 866,
        ),
        nearbyNetworks = nearbyNetworks,
        network = LocalScanResult.Network(
            ip = "192.168.1.2",
            gatewayIp = "192.168.1.1",
            dnsServers = listOf("192.168.1.1"),
            vpnActive = vpnActive,
        ),
        hosts = hosts,
        latencyMs = latencyMs,
    )

    private fun nearby(count: Int) = (1..count).map {
        LocalScanResult.NearbyNetwork(
            ssid = "AP$it",
            bssid = "aa:bb:cc:dd:ee:0$it",
            security = "WPA2",
            channel = 36,
            band = "5 GHz",
            signal = -60,
        )
    }

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
    fun mixedWpaWpa2IsLow() {
        // Mixed mode is downgraded-but-encrypted — a LOW nudge, not the HIGH
        // raised for WPA-only (mirrors the CLI's isWeakSecurity exclusion).
        val analysis = LocalAnalyser.analyse(result(security = "WPA/WPA2"))
        assertEquals(Severity.LOW, analysis.overallRisk)
        assertTrue(analysis.findings.any { it.title.contains("Mixed WPA/WPA2") })
    }

    @Test
    fun wpa3TransitionModeIsInfo() {
        val analysis = LocalAnalyser.analyse(result(security = "WPA2/WPA3"))
        assertEquals(Severity.INFO, analysis.overallRisk)
        assertTrue(analysis.findings.any { it.title.contains("transition", ignoreCase = true) })
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
    fun rtspHostIsFlaggedAsPossibleCamera() {
        // An open RTSP port is the low-confidence camera signal — surfaced with
        // the host named and hedged, since the phone can't confirm the vendor.
        val hosts = listOf(LocalScanResult.Host(ip = "192.168.1.20", openPorts = listOf(554)))
        val analysis = LocalAnalyser.analyse(result(security = "WPA2", hosts = hosts))
        val finding = analysis.findings.single { it.title.contains("camera", ignoreCase = true) }
        assertEquals(Severity.LOW, finding.severity)
        assertTrue(finding.detail.contains("192.168.1.20"))
        assertTrue(finding.detail.contains("RTSP"))
    }

    @Test
    fun altRtspPortIsFlaggedAsPossibleCamera() {
        // The alt RTSP port (8554) added to the sweep is treated the same as 554.
        val hosts = listOf(LocalScanResult.Host(ip = "192.168.1.21", openPorts = listOf(8554)))
        val analysis = LocalAnalyser.analyse(result(security = "WPA2", hosts = hosts))
        assertTrue(analysis.findings.any { it.title.contains("camera", ignoreCase = true) })
    }

    @Test
    fun rtspIsNotAlsoReportedAsCleartext() {
        // RTSP is surfaced once, as a camera hint (whose copy notes it's
        // unencrypted) — not additionally as a generic cleartext finding.
        val hosts = listOf(LocalScanResult.Host(ip = "192.168.1.20", openPorts = listOf(554)))
        val analysis = LocalAnalyser.analyse(result(security = "WPA2", hosts = hosts))
        assertTrue(analysis.findings.none { it.title.contains("Cleartext", ignoreCase = true) })
    }

    @Test
    fun nonRtspHostRaisesNoCameraFinding() {
        val hosts = listOf(LocalScanResult.Host(ip = "192.168.1.10", openPorts = listOf(80, 443)))
        val analysis = LocalAnalyser.analyse(result(security = "WPA2", hosts = hosts))
        assertTrue(analysis.findings.none { it.title.contains("camera", ignoreCase = true) })
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
    fun nearbyOnlySurveyReportsSurveyNotFailure() {
        // wifi null but the RF neighbourhood was captured: a deliberate survey,
        // not a failed read — the finding must reflect that honestly.
        val base = result(nearbyNetworks = nearby(3))
        val analysis = LocalAnalyser.analyse(base.copy(wifi = null))
        assertEquals(Severity.INFO, analysis.overallRisk)
        assertTrue(analysis.findings.any { it.title.contains("survey", ignoreCase = true) })
        assertTrue(analysis.findings.none { it.title.contains("unavailable", ignoreCase = true) })
    }

    @Test
    fun emptyButCollectedSurveyReportsSurveyNotFailure() {
        // A survey that ran with permission but saw no other APs (empty, non-null
        // list) is a survey, not a failed read — it must not tell the user to
        // grant a permission they already hold.
        val base = result(nearbyNetworks = emptyList())
        val analysis = LocalAnalyser.analyse(base.copy(wifi = null))
        assertEquals(Severity.INFO, analysis.overallRisk)
        assertTrue(analysis.findings.any { it.title.contains("survey", ignoreCase = true) })
        assertTrue(analysis.findings.none { it.title.contains("unavailable", ignoreCase = true) })
    }

    @Test
    fun nearbyOnlySurveyRaisesNoInsecureLinkFindings() {
        // A survey has no associated link, so no OPEN/WEP/VPN warnings should
        // be fabricated from the absent connection.
        val base = result(nearbyNetworks = nearby(2))
        val analysis = LocalAnalyser.analyse(base.copy(wifi = null))
        assertTrue(analysis.findings.none { it.title.contains("VPN", ignoreCase = true) })
        assertTrue(analysis.findings.none { it.title.contains("Open", ignoreCase = true) })
    }

    private fun nearby2_4(channel: Int, count: Int) = (1..count).map {
        LocalScanResult.NearbyNetwork(
            ssid = "AP$it",
            bssid = "aa:bb:cc:dd:e$channel:0$it",
            security = "WPA2",
            channel = channel,
            band = "2.4 GHz",
            signal = -60,
        )
    }

    @Test
    fun congested2_4ChannelRaisesInfoFinding() {
        // Connected on a busy 2.4 GHz channel 6 while channel 11 is clear — an
        // honest INFO nudge to retune.
        val analysis = LocalAnalyser.analyse(
            result(
                channel = 6,
                band = "2.4 GHz",
                // Crowd channel 6, one AP on channel 1, none on 11 — so channel
                // 11 is the unambiguous emptiest to suggest.
                nearbyNetworks = nearby2_4(6, 4) + nearby2_4(1, 1),
            ),
        )
        val finding = analysis.findings.single { it.title.contains("Congested", ignoreCase = true) }
        assertEquals(Severity.INFO, finding.severity)
        assertTrue(finding.detail.contains("channel 11"))
    }

    @Test
    fun quiet2_4ChannelRaisesNoCongestionFinding() {
        // One competing AP is below the margin — no congestion finding.
        val analysis = LocalAnalyser.analyse(
            result(channel = 6, band = "2.4 GHz", nearbyNetworks = nearby2_4(6, 1)),
        )
        assertTrue(analysis.findings.none { it.title.contains("Congested", ignoreCase = true) })
    }

    @Test
    fun fiveGhzConnectionRaisesNoCongestionFinding() {
        // A 5 GHz association has ample non-overlapping channels — never nagged,
        // even with a crowded 2.4 GHz neighbourhood.
        val analysis = LocalAnalyser.analyse(
            result(channel = 36, band = "5 GHz", nearbyNetworks = nearby2_4(6, 5)),
        )
        assertTrue(analysis.findings.none { it.title.contains("Congested", ignoreCase = true) })
    }

    @Test
    fun surveyModeRaisesNoCongestionFinding() {
        // No associated AP (survey mode): there is no channel to advise on, so no
        // congestion finding is fabricated even with a crowded neighbourhood.
        val base = result(channel = 6, band = "2.4 GHz", nearbyNetworks = nearby2_4(6, 5))
        val analysis = LocalAnalyser.analyse(base.copy(wifi = null))
        assertTrue(analysis.findings.none { it.title.contains("Congested", ignoreCase = true) })
    }

    /** A nearby AP advertising the connected SSID ("Net") — a potential twin. */
    private fun twin(
        security: String,
        suffix: Int = 1,
        channel: Int = 6,
        band: String = "2.4 GHz",
    ) = LocalScanResult.NearbyNetwork(
        ssid = "Net",
        bssid = "11:22:33:44:55:0$suffix",
        security = security,
        channel = channel,
        band = band,
        signal = -55,
    )

    @Test
    fun weakerTwinOfConnectedSsidRaisesMediumFinding() {
        // The connected WPA2 SSID also advertised nearby as Open — the classic
        // evil-twin shape, flagged at MEDIUM with the suspect BSSID named.
        val analysis = LocalAnalyser.analyse(
            result(security = "WPA2", nearbyNetworks = listOf(twin("Open"))),
        )
        val finding = analysis.findings.single { it.title.contains("twin", ignoreCase = true) }
        assertEquals(Severity.MEDIUM, finding.severity)
        assertTrue(finding.detail.contains("11:22:33:44:55:01"))
        assertTrue(finding.detail.contains("Open"))
        assertEquals(Severity.MEDIUM, analysis.overallRisk)
    }

    @Test
    fun strongerTwinOfConnectedSsidRaisesMediumFinding() {
        // The already-compromised vantage point: the phone joined the open
        // "Net" while a WPA2 "Net" is broadcasting nearby — the mismatch must
        // surface even though the nearby side is the stronger one.
        val analysis = LocalAnalyser.analyse(
            result(security = "Open", nearbyNetworks = listOf(twin("WPA2"))),
        )
        val finding = analysis.findings.single { it.title.contains("weakest", ignoreCase = true) }
        assertEquals(Severity.MEDIUM, finding.severity)
        assertTrue(finding.detail.contains("11:22:33:44:55:01"))
        assertTrue(finding.detail.contains("WPA2"))
    }

    @Test
    fun sameSecurityRoamingPartnersRaiseNoTwinFinding() {
        // Multi-BSSID alone is normal (mesh/roaming) — only a security
        // mismatch is the signal, so same-security partners raise nothing.
        val analysis = LocalAnalyser.analyse(
            result(security = "WPA2", nearbyNetworks = listOf(twin("WPA2"), twin("WPA2", 2))),
        )
        assertTrue(analysis.findings.none { it.title.contains("twin", ignoreCase = true) })
        assertTrue(analysis.findings.none { it.title.contains("weakest", ignoreCase = true) })
    }

    @Test
    fun surveyModeRaisesNoTwinFinding() {
        // No associated AP (survey mode): there is no joined link to be a twin
        // of, so no finding is fabricated even with a weaker duplicate nearby.
        val base = result(security = "WPA2", nearbyNetworks = listOf(twin("Open")))
        val analysis = LocalAnalyser.analyse(base.copy(wifi = null))
        assertTrue(analysis.findings.none { it.title.contains("twin", ignoreCase = true) })
        assertTrue(analysis.findings.none { it.title.contains("weakest", ignoreCase = true) })
    }

    @Test
    fun unknownChannelSentinelIsOmittedFromTwinDetail() {
        // A twin whose frequency couldn't be mapped carries the channel-0 /
        // unknown-band sentinels — the finding copy must not render "ch 0".
        val analysis = LocalAnalyser.analyse(
            result(
                security = "WPA2",
                nearbyNetworks = listOf(twin("Open", channel = 0, band = "unknown")),
            ),
        )
        val finding = analysis.findings.single { it.title.contains("twin", ignoreCase = true) }
        assertTrue(finding.detail.contains("11:22:33:44:55:01"))
        assertTrue(!finding.detail.contains("ch 0"))
    }

    @Test
    fun unknownTwinSecurityRaisesNoTwinFinding() {
        // An unknown label is not comparable — never claimed as a downgrade.
        val analysis = LocalAnalyser.analyse(
            result(security = "WPA2", nearbyNetworks = listOf(twin("unknown"))),
        )
        assertTrue(analysis.findings.none { it.title.contains("twin", ignoreCase = true) })
    }

    @Test
    fun findingsAreSortedBySeverity() {
        val hosts = listOf(LocalScanResult.Host(ip = "192.168.1.10", openPorts = listOf(80)))
        val analysis = LocalAnalyser.analyse(result(security = "Open", hosts = hosts, latencyMs = 500))
        val ordinals = analysis.findings.map { it.severity.ordinal }
        assertEquals(ordinals.sorted(), ordinals)
    }
}
