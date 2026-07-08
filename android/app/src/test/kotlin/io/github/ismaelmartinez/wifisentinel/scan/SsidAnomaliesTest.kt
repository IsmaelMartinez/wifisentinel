package io.github.ismaelmartinez.wifisentinel.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for [SsidAnomalies] — the duplicate-SSID grouping and
 * mismatched-twin (possible evil twin) logic behind the RF-neighbourhood
 * security view. No Android framework types are touched, so these run under
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

    private fun wifi(
        ssid: String? = "Home",
        bssid: String? = "11:22:33:44:55:66",
        security: String = "WPA2",
    ) = LocalScanResult.Wifi(
        ssid = ssid,
        bssid = bssid,
        security = security,
        channel = 6,
        band = "2.4 GHz",
        signal = -50,
        txRate = 866,
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
    fun hiddenAndBlankNetworksAreNeverGrouped() {
        // Hidden (null) and whitespace-only SSIDs are indistinguishable across
        // APs — grouping them would fabricate a multi-BSSID SSID that may not
        // exist (and a blank name renders as nothing in the UI row).
        val duplicates = SsidAnomalies.duplicates(
            listOf(net(null), net(null), net(" "), net(" ")),
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

    // ---- duplicates: the connected AP ------------------------------------------

    @Test
    fun connectedApCountsTowardItsSsidGroup() {
        // The nearby list excludes the connected BSSID by construction, so the
        // canonical single-twin case (joined WPA2 "Home", one Open "Home"
        // nearby) has only one nearby member. With the connected AP handed in,
        // the group is 2 APs with mixed security — visible, not hidden.
        val duplicates = SsidAnomalies.duplicates(
            listOf(net("Home", security = "Open")),
            connected = wifi(ssid = "Home", security = "WPA2"),
        )
        val home = duplicates.single()
        assertEquals(2, home.bssidCount)
        assertTrue(home.mixedSecurity)
        assertEquals(listOf("Open", "WPA2"), home.securities)
    }

    @Test
    fun connectedApAloneIsNotADuplicate() {
        // Joined to "Home" with no same-name AP nearby: nothing multi-homed.
        val duplicates = SsidAnomalies.duplicates(
            listOf(net("Cafe")),
            connected = wifi(ssid = "Home"),
        )
        assertTrue(duplicates.isEmpty())
    }

    @Test
    fun redactedConnectedBssidIsNotAdded() {
        // A null connected BSSID could not have been excluded from the nearby
        // list, so adding it back could double-count the same radio.
        val duplicates = SsidAnomalies.duplicates(
            listOf(net("Home")),
            connected = wifi(ssid = "Home", bssid = null),
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
    fun mixedModeLabelsRankBelowThePureNewerProtocol() {
        // "WPA/WPA2" sits between WPA and WPA2, "WPA2/WPA3" between WPA2 and
        // WPA3 — same rungs as the CLI's FAMILY_STRENGTH, so a mixed-mode
        // downgrade twin of a pure network is a real mismatch.
        val duplicates = SsidAnomalies.duplicates(
            listOf(net("Home", security = "WPA2"), net("Home", security = "WPA/WPA2")),
        )
        assertTrue(duplicates.single().mixedSecurity)
        assertEquals(listOf("WPA/WPA2", "WPA2"), duplicates.single().securities)
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

    // ---- mismatchedTwins: the evil-twin shape -----------------------------------

    @Test
    fun openTwinOfConnectedWpa2SsidIsWeaker() {
        val twins = SsidAnomalies.mismatchedTwins(
            connectedSsid = "Home",
            connectedSecurity = "WPA2",
            nearby = listOf(net("Home", security = "Open"), net("Cafe", security = "Open")),
        )
        val twin = twins.single()
        assertEquals("Home", twin.network.ssid)
        assertEquals("Open", twin.network.security)
        assertEquals(SsidAnomalies.Mismatch.WEAKER, twin.mismatch)
    }

    @Test
    fun strongerTwinIsFlaggedAsStronger() {
        // The already-compromised vantage point: the phone has joined the open
        // twin and the legitimate WPA2 AP is still broadcasting nearby. The
        // mismatch must surface, direction STRONGER.
        val twins = SsidAnomalies.mismatchedTwins(
            connectedSsid = "Home",
            connectedSecurity = "Open",
            nearby = listOf(net("Home", security = "WPA2")),
        )
        assertEquals(SsidAnomalies.Mismatch.STRONGER, twins.single().mismatch)
    }

    @Test
    fun sameSecurityRoamingPartnerIsNotFlagged() {
        // The false-positive guard: another WPA2 BSSID on the connected SSID is
        // ordinary mesh/roaming infrastructure, not an evil twin.
        val twins = SsidAnomalies.mismatchedTwins(
            connectedSsid = "Home",
            connectedSecurity = "WPA2",
            nearby = listOf(net("Home", security = "WPA2"), net("Home", security = "WPA2")),
        )
        assertTrue(twins.isEmpty())
    }

    @Test
    fun differentSsidIsNeverATwin() {
        val twins = SsidAnomalies.mismatchedTwins(
            connectedSsid = "Home",
            connectedSecurity = "WPA2",
            nearby = listOf(net("Cafe", security = "Open")),
        )
        assertTrue(twins.isEmpty())
    }

    @Test
    fun unknownSecurityOnEitherSideIsNotComparable() {
        // Refuse to claim a mismatch that can't be measured — matches the CLI's
        // isWeakerSecurity treatment of unknown labels.
        assertTrue(
            SsidAnomalies.mismatchedTwins(
                connectedSsid = "Home",
                connectedSecurity = "unknown",
                nearby = listOf(net("Home", security = "Open")),
            ).isEmpty(),
        )
        assertTrue(
            SsidAnomalies.mismatchedTwins(
                connectedSsid = "Home",
                connectedSecurity = "WPA2",
                nearby = listOf(net("Home", security = "unknown")),
            ).isEmpty(),
        )
    }

    @Test
    fun nullOrBlankConnectedSsidFlagsNothing() {
        // Survey mode / hidden or whitespace-only connected SSID: nothing to
        // compare against.
        val nearby = listOf(net("Home", security = "Open"))
        assertTrue(SsidAnomalies.mismatchedTwins(null, "WPA2", nearby).isEmpty())
        assertTrue(SsidAnomalies.mismatchedTwins(" ", "WPA2", nearby).isEmpty())
    }

    @Test
    fun wepTwinOfWpa3SsidIsWeaker() {
        // Strength ladder spans the whole family order, not just Open-vs-rest.
        val twins = SsidAnomalies.mismatchedTwins(
            connectedSsid = "Home",
            connectedSecurity = "WPA3",
            nearby = listOf(net("Home", security = "WEP")),
        )
        assertEquals("WEP", twins.single().network.security)
        assertEquals(SsidAnomalies.Mismatch.WEAKER, twins.single().mismatch)
    }

    @Test
    fun enhancedOpenRanksBelowWpa2() {
        // OWE is encrypted but unauthenticated — same rung as the CLI's ladder
        // (open < wep < owe < wpa < wpa/wpa2 < wpa2 < wpa2/wpa3 < wpa3).
        val twins = SsidAnomalies.mismatchedTwins(
            connectedSsid = "Home",
            connectedSecurity = "WPA2",
            nearby = listOf(net("Home", security = "Enhanced Open")),
        )
        assertEquals("Enhanced Open", twins.single().network.security)
        assertEquals(SsidAnomalies.Mismatch.WEAKER, twins.single().mismatch)
    }

    @Test
    fun mixedModeTwinOfPureWpa2IsWeaker() {
        // A WPA/WPA2 mixed-mode twin keeps the crackable TKIP handshake
        // negotiable — the CLI rates this a downgrade, and so does the phone.
        val twins = SsidAnomalies.mismatchedTwins(
            connectedSsid = "Home",
            connectedSecurity = "WPA2",
            nearby = listOf(net("Home", security = "WPA/WPA2")),
        )
        assertEquals(SsidAnomalies.Mismatch.WEAKER, twins.single().mismatch)
    }

    @Test
    fun twinsAreSortedStrongestSignalFirst() {
        val twins = SsidAnomalies.mismatchedTwins(
            connectedSsid = "Home",
            connectedSecurity = "WPA2",
            nearby = listOf(
                net("Home", security = "Open", signal = -80),
                net("Home", security = "WEP", signal = -40),
            ),
        )
        assertEquals(listOf(-40, -80), twins.map { it.network.signal })
    }

    // ---- vocabulary anchor -----------------------------------------------------

    @Test
    fun everyProducedSecurityLabelIsOnTheStrengthLadder() {
        // Anchor the ladder to the producer: every non-"unknown" label
        // WifiMapping.securityFromCapabilities can emit must be comparable,
        // otherwise a new label silently disables twin/mixed detection for
        // exactly the networks it describes. Representative capability strings
        // cover every branch of the producer.
        val representativeCaps = listOf(
            "[RSN-SAE-CCMP][ESS]", // WPA3
            "[WPA2-PSK][RSN-SAE+PSK-CCMP][ESS]", // WPA2/WPA3
            "[RSN-OWE-CCMP][ESS]", // Enhanced Open
            "[WPA2-PSK-CCMP][ESS]", // WPA2
            "[WPA-PSK-TKIP][WPA2-PSK-CCMP][ESS]", // WPA/WPA2
            "[WPA-PSK-TKIP][ESS]", // WPA
            "[WEP][ESS]", // WEP
            "[ESS]", // Open
        )
        for (caps in representativeCaps) {
            val label = WifiMapping.securityFromCapabilities(caps)
            // A pair of the produced label and a label from the opposite end of
            // the ladder must register as mixed — which requires both to be on
            // the ladder.
            val other = if (label == "Open") "WPA3" else "Open"
            val duplicates = SsidAnomalies.duplicates(
                listOf(net("Anchor", security = label), net("Anchor", security = other)),
            )
            assertTrue(
                "label \"$label\" (from $caps) has no strength rung",
                duplicates.single().mixedSecurity,
            )
        }
    }
}
