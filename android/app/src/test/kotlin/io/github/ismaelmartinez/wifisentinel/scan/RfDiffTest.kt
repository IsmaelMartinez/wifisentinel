package io.github.ismaelmartinez.wifisentinel.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for [RfDiff] — the since-last-scan diff of the RF
 * neighbourhood. No Android framework types are touched, so these run under
 * `./gradlew test` without an emulator (same rationale as the other JVM
 * tests). See docs/android-companion.md §9.
 */
class RfDiffTest {

    private fun net(
        bssid: String,
        ssid: String? = "Home",
        security: String = "WPA2",
        signal: Int = -60,
        channel: Int = 6,
        band: String = "2.4 GHz",
    ) = LocalScanResult.NearbyNetwork(
        ssid = ssid,
        bssid = bssid,
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

    // ---- basics -----------------------------------------------------------------

    @Test
    fun identicalNeighbourhoodsDiffEmpty() {
        val nearby = listOf(net("aa:00::01"), net("aa:00::02", ssid = "Cafe"))
        val diff = RfDiff.diff(nearby, nearby)
        assertTrue(diff.isEmpty)
        assertTrue(diff.appeared.isEmpty())
        assertTrue(diff.vanished.isEmpty())
        assertTrue(diff.securityChanges.isEmpty())
    }

    @Test
    fun emptyPredecessorListsEveryCurrentApAsAppeared() {
        // A predecessor that collected an empty neighbourhood (emulator, or a
        // denied fresh scan) is still comparable — everything now visible
        // appeared, and nothing on a "known" SSID because nothing was known.
        val diff = RfDiff.diff(emptyList(), listOf(net("aa:00::01"), net("aa:00::02")))
        assertEquals(2, diff.appeared.size)
        assertTrue(diff.appeared.none { it.onKnownSsid })
        assertTrue(diff.vanished.isEmpty())
    }

    @Test
    fun emptyCurrentListsEveryPreviousApAsVanished() {
        val diff = RfDiff.diff(listOf(net("aa:00::01")), emptyList())
        assertTrue(diff.appeared.isEmpty())
        assertEquals(1, diff.vanished.size)
        assertFalse(diff.isEmpty)
    }

    @Test
    fun appearedAndVanishedAreKeyedByBssidNotSsid() {
        // Same SSID, different radio: the BSSID is the identity. One AP of the
        // mesh went away, another came up — both reported, keyed apart.
        val diff = RfDiff.diff(
            listOf(net("aa:00::01", ssid = "Mesh")),
            listOf(net("aa:00::02", ssid = "Mesh")),
        )
        assertEquals("aa:00::02", diff.appeared.single().network.bssid)
        assertEquals("aa:00::01", diff.vanished.single().bssid)
    }

    @Test
    fun bssidMatchingIsCaseInsensitive() {
        // Sources disagree on BSSID case (the CLI's apKey lowercases for the
        // same reason) — a case change must not read as appeared+vanished.
        val diff = RfDiff.diff(
            listOf(net("AA:BB:CC:DD:EE:01")),
            listOf(net("aa:bb:cc:dd:ee:01")),
        )
        assertTrue(diff.isEmpty)
    }

    // ---- the known-SSID appearance flag ------------------------------------------

    @Test
    fun newBssidOnKnownSsidIsFlagged() {
        // The signal case: the previous scan knew "Home" on one radio; now a
        // second radio advertises it. Stronger twin hint than one snapshot.
        val diff = RfDiff.diff(
            listOf(net("aa:00::01", ssid = "Home")),
            listOf(net("aa:00::01", ssid = "Home"), net("aa:00::02", ssid = "Home")),
        )
        val appeared = diff.appeared.single()
        assertEquals("aa:00::02", appeared.network.bssid)
        assertTrue(appeared.onKnownSsid)
    }

    @Test
    fun newBssidOnNewSsidIsNotFlagged() {
        val diff = RfDiff.diff(
            listOf(net("aa:00::01", ssid = "Home")),
            listOf(net("aa:00::01", ssid = "Home"), net("aa:00::02", ssid = "Cafe")),
        )
        assertFalse(diff.appeared.single().onKnownSsid)
    }

    @Test
    fun previousConnectedSsidCountsAsKnown() {
        // The previous scan's joined SSID is excluded from its own nearby list
        // by construction — it must still count as "known", because a new
        // BSSID on the SSID you were connected to is exactly the twin case.
        val diff = RfDiff.diff(
            previousNearby = listOf(net("aa:00::01", ssid = "Cafe")),
            currentNearby = listOf(net("aa:00::01", ssid = "Cafe"), net("aa:00::02", ssid = "Home")),
            previousConnected = wifi(ssid = "Home", bssid = "11:22:33:44:55:66"),
        )
        val appeared = diff.appeared.single()
        assertEquals("Home", appeared.network.ssid)
        assertTrue(appeared.onKnownSsid)
    }

    @Test
    fun hiddenSsidNeverMatchesAsKnown() {
        // Hidden (null) and blank SSIDs are not usable names — a "known SSID"
        // match on them would be fabricated (same rationale as SsidAnomalies).
        val diff = RfDiff.diff(
            listOf(net("aa:00::01", ssid = null), net("aa:00::02", ssid = " ")),
            listOf(
                net("aa:00::01", ssid = null),
                net("aa:00::02", ssid = " "),
                net("aa:00::03", ssid = null),
                net("aa:00::04", ssid = " "),
            ),
        )
        assertEquals(2, diff.appeared.size)
        assertTrue(diff.appeared.none { it.onKnownSsid })
    }

    // ---- the connected-AP fold ----------------------------------------------------

    @Test
    fun roamingBetweenScansDoesNotFabricateAppearance() {
        // Previously connected to radio A (so A was excluded from the previous
        // nearby list); now connected to B with A visible nearby. Without the
        // fold, A would read as "appeared" — it was there all along.
        val diff = RfDiff.diff(
            previousNearby = listOf(net("bb:00::02", ssid = "Home")),
            currentNearby = listOf(net("aa:00::01", ssid = "Home")),
            previousConnected = wifi(ssid = "Home", bssid = "aa:00::01"),
            currentConnected = wifi(ssid = "Home", bssid = "bb:00::02"),
        )
        assertTrue(diff.isEmpty)
    }

    @Test
    fun currentConnectedApIsItselfDiffed() {
        // The AP the phone is on now wasn't anywhere in the previous scan —
        // that appearance (on the known, previously-connected SSID) must not
        // be hidden just because the current nearby list excludes it.
        val diff = RfDiff.diff(
            previousNearby = emptyList(),
            currentNearby = emptyList(),
            previousConnected = wifi(ssid = "Home", bssid = "aa:00::01"),
            currentConnected = wifi(ssid = "Home", bssid = "bb:00::02"),
        )
        val appeared = diff.appeared.single()
        assertEquals("bb:00::02", appeared.network.bssid)
        assertTrue(appeared.onKnownSsid)
        assertEquals("aa:00::01", diff.vanished.single().bssid)
    }

    @Test
    fun redactedConnectedBssidIsNotFolded() {
        // A null BSSID could not have been excluded from the nearby list, so
        // folding it back could double-count a radio. Survey mode (null wifi)
        // takes the same path.
        val diff = RfDiff.diff(
            previousNearby = listOf(net("aa:00::01")),
            currentNearby = listOf(net("aa:00::01")),
            previousConnected = wifi(bssid = null),
            currentConnected = null,
        )
        assertTrue(diff.isEmpty)
    }

    // ---- security changes -----------------------------------------------------------

    @Test
    fun familyChangeOnMatchedBssidIsReported() {
        val diff = RfDiff.diff(
            listOf(net("aa:00::01", security = "WPA2")),
            listOf(net("aa:00::01", security = "Open")),
        )
        val change = diff.securityChanges.single()
        assertEquals("WPA2", change.previousSecurity)
        assertEquals("Open", change.network.security)
        assertTrue(diff.appeared.isEmpty() && diff.vanished.isEmpty())
    }

    @Test
    fun mixedModeToPureIsAFamilyChange() {
        // "WPA/WPA2" and "WPA2" are different rungs (the older handshake stays
        // negotiable) — same taxonomy as the CLI's FAMILY_STRENGTH.
        val diff = RfDiff.diff(
            listOf(net("aa:00::01", security = "WPA/WPA2")),
            listOf(net("aa:00::01", security = "WPA2")),
        )
        assertEquals(1, diff.securityChanges.size)
    }

    @Test
    fun unknownSecurityOnEitherSideIsNeverAChange() {
        // Mirrors the CLI's securityChanged: an unmeasured label must not
        // manufacture a change in either direction.
        val toUnknown = RfDiff.diff(
            listOf(net("aa:00::01", security = "WPA2")),
            listOf(net("aa:00::01", security = "unknown")),
        )
        assertTrue(toUnknown.isEmpty)
        val fromUnknown = RfDiff.diff(
            listOf(net("aa:00::01", security = "unknown")),
            listOf(net("aa:00::01", security = "Open")),
        )
        assertTrue(fromUnknown.isEmpty)
    }

    @Test
    fun sameFamilyIsNeverAChange() {
        val diff = RfDiff.diff(
            listOf(net("aa:00::01", security = "WPA2")),
            listOf(net("aa:00::01", security = "wpa2")),
        )
        assertTrue(diff.isEmpty)
    }

    @Test
    fun connectedApSecurityChangeIsDetectedThroughTheFold() {
        // The joined AP downgraded between scans; both sides know it only via
        // the connected fold (excluded from both nearby lists).
        val diff = RfDiff.diff(
            previousNearby = emptyList(),
            currentNearby = emptyList(),
            previousConnected = wifi(security = "WPA2"),
            currentConnected = wifi(security = "Open"),
        )
        assertEquals("WPA2", diff.securityChanges.single().previousSecurity)
    }

    // ---- ordering ----------------------------------------------------------------

    @Test
    fun appearedSortsKnownSsidFirstThenStrongestSignal() {
        val diff = RfDiff.diff(
            listOf(net("aa:00::01", ssid = "Home")),
            listOf(
                net("aa:00::01", ssid = "Home"),
                net("aa:00::02", ssid = "Cafe", signal = -40),
                net("aa:00::03", ssid = "Home", signal = -80),
                net("aa:00::04", ssid = "Cafe", signal = -70),
            ),
        )
        assertEquals(
            listOf("aa:00::03", "aa:00::02", "aa:00::04"),
            diff.appeared.map { it.network.bssid },
        )
    }

    @Test
    fun vanishedSortsStrongestPreviousSightingFirst() {
        val diff = RfDiff.diff(
            listOf(net("aa:00::01", signal = -80), net("aa:00::02", signal = -40)),
            emptyList(),
        )
        assertEquals(listOf("aa:00::02", "aa:00::01"), diff.vanished.map { it.bssid })
    }
}
