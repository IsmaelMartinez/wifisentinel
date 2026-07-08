package io.github.ismaelmartinez.wifisentinel.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for [ChannelCongestion] — the bucketing and least-congested
 * logic behind the RF-neighbourhood congestion view. No Android framework types
 * are touched, so these run under `./gradlew test` without an emulator (same
 * rationale as the other JVM tests). See docs/android-companion.md §9.
 */
class ChannelCongestionTest {

    private fun net(
        channel: Int,
        band: String = ChannelCongestion.BAND_2_4,
        bssid: String = "aa:bb:cc:dd:ee:%02x".format(channel),
    ) = LocalScanResult.NearbyNetwork(
        ssid = "AP",
        bssid = bssid,
        security = "WPA2",
        channel = channel,
        band = band,
        signal = -60,
    )

    // ---- bucketing / occupancy ----------------------------------------------

    @Test
    fun emptyListSummarisesToEmpty() {
        val summary = ChannelCongestion.summarise(emptyList())
        assertTrue(summary.isEmpty)
        assertEquals(emptyList<Int>(), summary.leastCongested2_4)
        assertTrue(summary.occupancy.isEmpty())
    }

    @Test
    fun countsOccupancyPerBandAndChannel() {
        val summary = ChannelCongestion.summarise(
            listOf(
                net(1), net(1), net(6),
                net(36, band = "5 GHz"),
            ),
        )
        assertEquals(
            listOf(
                ChannelCongestion.ChannelOccupancy("2.4 GHz", 1, 2),
                ChannelCongestion.ChannelOccupancy("2.4 GHz", 6, 1),
                ChannelCongestion.ChannelOccupancy("5 GHz", 36, 1),
            ),
            summary.occupancy,
        )
    }

    @Test
    fun occupancyIsOrderedByBandThenChannel() {
        val summary = ChannelCongestion.summarise(
            listOf(
                net(40, band = "5 GHz"),
                net(11),
                net(1),
                net(2, band = "6 GHz"),
                net(3, band = "unknown"),
            ),
        )
        assertEquals(
            listOf(
                "2.4 GHz" to 1,
                "2.4 GHz" to 11,
                "5 GHz" to 40,
                "6 GHz" to 2,
                "unknown" to 3, // unknown band sorts last
            ),
            summary.occupancy.map { it.band to it.channel },
        )
    }

    @Test
    fun channelZeroCountsInOccupancyButNotOverlapMaths() {
        // A 2.4 GHz frequency outside the standard channel ranges maps to the
        // channel-0 sentinel (WifiMapping). It's still a real network for the
        // occupancy display, but has no centre to overlap 1/6/11 — it must not
        // skew the pick.
        val summary = ChannelCongestion.summarise(
            listOf(
                net(0, bssid = "aa:bb:cc:dd:ee:01"),
                net(0, bssid = "aa:bb:cc:dd:ee:02"),
                net(1),
            ),
        )
        assertEquals(2, summary.occupancy.single { it.channel == 0 }.count)
        // Only the channel-1 network feeds the overlap maths.
        assertEquals(1, summary.overlapCounts2_4[1])
        assertEquals(0, summary.overlapCounts2_4[6])
        assertEquals(0, summary.overlapCounts2_4[11])
        assertEquals(listOf(6, 11), summary.leastCongested2_4)
    }

    @Test
    fun channelZeroOnlyMeansNoLeastCongested() {
        // Nothing but unknown-channel 2.4 GHz entries: no real channel to weigh,
        // so no recommendation (but the buckets still show).
        val summary = ChannelCongestion.summarise(
            listOf(net(0, bssid = "aa:bb:cc:dd:ee:01")),
        )
        assertEquals(emptyList<Int>(), summary.leastCongested2_4)
        assertTrue(summary.overlapCounts2_4.isEmpty())
        assertEquals(1, summary.occupancy.single().count)
    }

    // ---- least-congested 2.4 GHz --------------------------------------------

    @Test
    fun picksEmptiestNonOverlappingChannel() {
        // Crowd channels 1 and 6; channel 11 stays clear.
        val summary = ChannelCongestion.summarise(
            listOf(net(1), net(1), net(6), net(6), net(6)),
        )
        assertEquals(listOf(11), summary.leastCongested2_4)
    }

    @Test
    fun overlapCountsSpreadAcrossNeighbouringChannels() {
        // A single AP on channel 3 overlaps both candidate 1 (|3-1|=2) and
        // candidate 6 (|3-6|=3), but not 11. Channel 11 is therefore emptiest.
        val summary = ChannelCongestion.summarise(listOf(net(3)))
        assertEquals(1, summary.overlapCounts2_4[1])
        assertEquals(1, summary.overlapCounts2_4[6])
        assertEquals(0, summary.overlapCounts2_4[11])
        assertEquals(listOf(11), summary.leastCongested2_4)
    }

    @Test
    fun tiesListAllEmptiestChannels() {
        // Only channel 6 occupied: candidates 1 and 11 are equally clear
        // (|6-1|=5 and |6-11|=5 are both beyond the overlap radius of 4).
        val summary = ChannelCongestion.summarise(listOf(net(6)))
        assertEquals(listOf(1, 11), summary.leastCongested2_4)
    }

    @Test
    fun noTwoPointFourDataMeansNoLeastCongested() {
        val summary = ChannelCongestion.summarise(
            listOf(net(36, band = "5 GHz"), net(40, band = "5 GHz")),
        )
        assertEquals(emptyList<Int>(), summary.leastCongested2_4)
        assertTrue(summary.overlapCounts2_4.isEmpty())
        // 5 GHz still bucketed for the occupancy display.
        assertEquals(2, summary.occupancy.size)
    }

    @Test
    fun fiveGhzChannelsDoNotAffectTwoPointFourPick() {
        val summary = ChannelCongestion.summarise(
            listOf(net(1), net(6), net(149, band = "5 GHz"), net(149, band = "5 GHz")),
        )
        // Only 1 and 6 seen on 2.4 GHz, so 11 is emptiest regardless of 5 GHz.
        assertEquals(listOf(11), summary.leastCongested2_4)
    }

    // ---- move suggestion -----------------------------------------------------

    @Test
    fun suggestsMoveOffCongestedChannel() {
        // Connected on channel 6, which overlaps four nearby APs; channel 1 has
        // one and channel 11 is clear, so channel 11 is the unique emptiest.
        val nearby = listOf(net(6), net(6), net(6), net(6), net(1))
        val suggestion = ChannelCongestion.suggestLessCongestedChannel(
            connectedChannel = 6,
            connectedBand = ChannelCongestion.BAND_2_4,
            nearby = nearby,
        )
        assertEquals(6, suggestion?.connectedChannel)
        assertEquals(4, suggestion?.connectedOccupancy)
        assertEquals(11, suggestion?.suggestedChannel)
        assertEquals(0, suggestion?.suggestedOccupancy)
    }

    @Test
    fun noSuggestionWhenChannelIsAlreadyQuiet() {
        // One competing AP on channel 6 is below the margin — no nagging.
        val suggestion = ChannelCongestion.suggestLessCongestedChannel(
            connectedChannel = 6,
            connectedBand = ChannelCongestion.BAND_2_4,
            nearby = listOf(net(6)),
        )
        assertNull(suggestion)
    }

    @Test
    fun noSuggestionWhenGapIsBelowMargin() {
        // Connected channel 6 overlaps 2; channels 1 and 11 each overlap 1. The
        // best gap (2 → 1) is below the default margin of two, so no move is
        // suggested.
        val suggestion = ChannelCongestion.suggestLessCongestedChannel(
            connectedChannel = 6,
            connectedBand = ChannelCongestion.BAND_2_4,
            nearby = listOf(net(6), net(6), net(1), net(11)),
        )
        assertNull(suggestion)
    }

    @Test
    fun noSuggestionOffTwoPointFourBand() {
        // A 5 GHz association is never nagged — plenty of non-overlapping room.
        val suggestion = ChannelCongestion.suggestLessCongestedChannel(
            connectedChannel = 36,
            connectedBand = "5 GHz",
            nearby = listOf(net(1), net(6), net(11)),
        )
        assertNull(suggestion)
    }

    @Test
    fun noSuggestionWhenConnectedChannelIsUnknown() {
        // Connected channel 0 (unknown 2.4 GHz frequency): no defined channel to
        // advise on, so no suggestion even amid a crowd.
        val suggestion = ChannelCongestion.suggestLessCongestedChannel(
            connectedChannel = 0,
            connectedBand = ChannelCongestion.BAND_2_4,
            nearby = listOf(net(6), net(6), net(6)),
        )
        assertNull(suggestion)
    }

    @Test
    fun noSuggestionWhenNoNearbyNetworks() {
        val suggestion = ChannelCongestion.suggestLessCongestedChannel(
            connectedChannel = 6,
            connectedBand = ChannelCongestion.BAND_2_4,
            nearby = emptyList(),
        )
        assertNull(suggestion)
    }

    @Test
    fun noSuggestionWhenEveryChannelIsEquallyCongested() {
        // Two APs on each of 1/6/11: the connected channel is congested (overlap
        // 2) but every non-overlapping channel is just as busy, so there is
        // nowhere clearly better — no move is suggested.
        val nearby = listOf(net(1), net(1), net(6), net(6), net(11), net(11))
        val suggestion = ChannelCongestion.suggestLessCongestedChannel(
            connectedChannel = 6,
            connectedBand = ChannelCongestion.BAND_2_4,
            nearby = nearby,
        )
        assertNull(suggestion)
    }
}
