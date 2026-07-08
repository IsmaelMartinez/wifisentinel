package io.github.ismaelmartinez.wifisentinel.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for [SsidAnomalies] — the duplicate-SSID grouping and
 * weaker-twin (possible evil twin) logic behind the RF-neighbourhood security
 * view. No Android framework types are touched, so these run under
 * `./gradlew test` without an emulator (same rationale as the other JVM
 * tests). See docs/android-companion.md §9.
 */
class SsidAnomaliesTest {

    private var bssidSeq = 0

    private fun net(
        ssid: String?,
        security: String = "WPA2",
        signal: Int = -60,
        channel: Int = 6,
        band: String = "2.4 GHz",
    ) = LocalScanResult.NearbyNetwork(
        ssid = ssid,
        bssid = "aa:bb:cc:dd:ee:%02x".format(bssidSeq++),
        security = security,
        channel = channel,
        band = band,
        signal = signal,
    )

    // ---- duplicates: grouping -------------------------------------------------

    @Test
    fun emptyListHasNoDuplicates() {
        assertTrue(SsidAnomalies.duplicates(emptyList()).isEmpty())
    }

    @Test
    fun singleBssidPerSsidIsNotDuplicate() {
        val duplicates = SsidAnomalies.duplicates(
            listOf(net("Home"), net("Cafe"), net("Office")),
        )
        assertTrue(duplicates.isEmpty())
    }

    @Test
    fun multiBssidSsidIsGroupedWithCount() {
        val duplicates = SsidAnomalies.duplicates(
            listOf(net("Home"), net("Home"), net("Home"), net("Cafe")),
        )
        val home = duplicates.single()
        assertEquals("Home", home.ssid)
        assertEquals(3, home.bssidCount)
    }

    @Test
    fun hiddenNetworksAreNeverGrouped() {
        // Two hidden networks (null SSID) are indistinguishable — grouping them
        // would fabricate a multi-BSSID SSID that may not exist.
        val duplicates = SsidAnomalies.duplicates(
            listOf(net(null), net(null), net(null)),
        )
        assertTrue(duplicates.isEmpty())
    }

    @Test
    fun ssidGroupingIsCaseSensitive() {
        // SSIDs are byte strings; "home" and "Home" are distinct networks, and
        // the CLI's rogue-ap rule compares exactly — same here, no over-claiming.
        val duplicates = SsidAnomalies.duplicates(
            listOf(net("Home"), net("home")),
        )
        assertTrue(duplicates.isEmpty())
    }

    // ---- duplicates: the mixed-security signal --------------------------------

    @Test
    fun sameSecurityFleetIsNotMixed() {
        // A mesh / multi-AP roaming deployment: several BSSIDs, one SSID, one
        // security. Normal — listed, but never flagged as mixed.
        val duplicates = SsidAnomalies.duplicates(
            listOf(net("Mesh"), net("Mesh"), net("Mesh")),
        )
        assertFalse(duplicates.single().mixedSecurity)
    }

    @Test
    fun openTwinOfWpa2SsidIsMixed() {
        val duplicates = SsidAnomalies.duplicates(
            listOf(net("Home", security = "WPA2"), net("Home", security = "Open")),
        )
        val home = duplicates.single()
        assertTrue(home.mixedSecurity)
        // Weakest first for display.
        assertEquals(listOf("Open", "WPA2"), home.securities)
    }

    @Test
    fun wpa2AndWpa3SplitIsMixed() {
        // Honest: two different comparable families on one SSID is mixed, even
        // when both are encrypted.
        val duplicates = SsidAnomalies.duplicates(
            listOf(net("Home", security = "WPA3"), net("Home", security = "WPA2")),
        )
        assertTrue(duplicates.single().mixedSecurity)
        assertEquals(listOf("WPA2", "WPA3"), duplicates.single().securities)
    }

    @Test
    fun unknownSecurityDoesNotCreateMismatch() {
        // "unknown" is not comparable — it must not manufacture a mixed-security
        // flag against a known label.
        val duplicates = SsidAnomalies.duplicates(
            listOf(net("Home", security = "WPA2"), net("Home", security = "unknown")),
        )
        val home = duplicates.single()
        assertFalse(home.mixedSecurity)
        // Still listed for display, unrecognised label last.
        assertEquals(listOf("WPA2", "unknown"), home.securities)
    }

    @Test
    fun mixedEntriesSortFirst() {
        val duplicates = SsidAnomalies.duplicates(
            listOf(
                net("Mesh"), net("Mesh"), net("Mesh"),
                net("Home", security = "WPA2"), net("Home", security = "Open"),
            ),
        )
        assertEquals(listOf("Home", "Mesh"), duplicates.map { it.ssid })
    }

    @Test
    fun equalAnomalyRankSortsByCountThenSsid() {
        val duplicates = SsidAnomalies.duplicates(
            listOf(
                net("B"), net("B"),
                net("A"), net("A"),
                net("Big"), net("Big"), net("Big"),
            ),
        )
        assertEquals(listOf("Big", "A", "B"), duplicates.map { it.ssid })
    }

    // ---- weakerTwins: the evil-twin shape --------------------------------------

    @Test
    fun openTwinOfConnectedWpa2SsidIsFlagged() {
        val twins = SsidAnomalies.weakerTwins(
            connectedSsid = "Home",
            connectedSecurity = "WPA2",
            nearby = listOf(net("Home", security = "Open"), net("Cafe", security = "Open")),
        )
        val twin = twins.single()
        assertEquals("Home", twin.ssid)
        assertEquals("Open", twin.security)
    }

    @Test
    fun sameSecurityRoamingPartnerIsNotFlagged() {
        // The false-positive guard: another WPA2 BSSID on the connected SSID is
        // ordinary mesh/roaming infrastructure, not an evil twin.
        val twins = SsidAnomalies.weakerTwins(
            connectedSsid = "Home",
            connectedSecurity = "WPA2",
            nearby = listOf(net("Home", security = "WPA2"), net("Home", security = "WPA2")),
        )
        assertTrue(twins.isEmpty())
    }

    @Test
    fun strongerTwinIsNotFlagged() {
        // A WPA3 radio on the connected WPA2 SSID is an upgrade, not a downgrade.
        val twins = SsidAnomalies.weakerTwins(
            connectedSsid = "Home",
            connectedSecurity = "WPA2",
            nearby = listOf(net("Home", security = "WPA3")),
        )
        assertTrue(twins.isEmpty())
    }

    @Test
    fun differentSsidIsNeverATwin() {
        val twins = SsidAnomalies.weakerTwins(
            connectedSsid = "Home",
            connectedSecurity = "WPA2",
            nearby = listOf(net("Cafe", security = "Open")),
        )
        assertTrue(twins.isEmpty())
    }

    @Test
    fun unknownSecurityOnEitherSideIsNotComparable() {
        // Refuse to claim a downgrade that can't be measured — matches the CLI's
        // isWeakerSecurity treatment of unknown labels.
        assertTrue(
            SsidAnomalies.weakerTwins(
                connectedSsid = "Home",
                connectedSecurity = "unknown",
                nearby = listOf(net("Home", security = "Open")),
            ).isEmpty(),
        )
        assertTrue(
            SsidAnomalies.weakerTwins(
                connectedSsid = "Home",
                connectedSecurity = "WPA2",
                nearby = listOf(net("Home", security = "unknown")),
            ).isEmpty(),
        )
    }

    @Test
    fun nullConnectedSsidFlagsNothing() {
        // Survey mode / hidden connected SSID: nothing to compare against.
        val twins = SsidAnomalies.weakerTwins(
            connectedSsid = null,
            connectedSecurity = "WPA2",
            nearby = listOf(net("Home", security = "Open")),
        )
        assertTrue(twins.isEmpty())
    }

    @Test
    fun wepTwinOfWpa3SsidIsFlagged() {
        // Strength ladder spans the whole family order, not just Open-vs-rest.
        val twins = SsidAnomalies.weakerTwins(
            connectedSsid = "Home",
            connectedSecurity = "WPA3",
            nearby = listOf(net("Home", security = "WEP")),
        )
        assertEquals("WEP", twins.single().security)
    }

    @Test
    fun enhancedOpenRanksBelowWpa2() {
        // OWE is encrypted but unauthenticated — same rung as the CLI's ladder
        // (open < wep < owe < wpa < wpa2 < wpa3).
        val twins = SsidAnomalies.weakerTwins(
            connectedSsid = "Home",
            connectedSecurity = "WPA2",
            nearby = listOf(net("Home", security = "Enhanced Open")),
        )
        assertEquals("Enhanced Open", twins.single().security)
    }

    @Test
    fun twinsAreSortedStrongestSignalFirst() {
        val twins = SsidAnomalies.weakerTwins(
            connectedSsid = "Home",
            connectedSecurity = "WPA2",
            nearby = listOf(
                net("Home", security = "Open", signal = -80),
                net("Home", security = "WEP", signal = -40),
            ),
        )
        assertEquals(listOf(-40, -80), twins.map { it.signal })
    }
}
