package io.github.ismaelmartinez.wifisentinel.scan

/**
 * Pure, framework-free channel-congestion analysis for an RF neighbourhood —
 * the read a walk-around survey is actually for. Extracted (like
 * [WifiMapping] / [HostMerge] / [ScanPresentation]) so the bucketing and
 * least-congested logic can be JVM-unit-tested without a device. See
 * docs/android-companion.md §9.
 *
 * It buckets [LocalScanResult.NearbyNetwork]s by band + 802.11 channel, counts
 * occupancy per channel, and — for the 2.4 GHz band, where 20 MHz channels
 * overlap and channel choice actually matters — picks the least-congested of
 * the non-overlapping channels 1/6/11.
 *
 * Returns typed descriptors only; all UI copy stays in `strings.xml`.
 */
object ChannelCongestion {

    /** Band label (matching [WifiMapping.frequencyToBand]) for the 2.4 GHz band. */
    const val BAND_2_4 = "2.4 GHz"

    /**
     * The three mutually non-overlapping 2.4 GHz channels (IEEE 802.11, 20 MHz
     * spacing). A survey should aim traffic at whichever of these is emptiest.
     */
    val NON_OVERLAPPING_2_4 = listOf(1, 6, 11)

    /**
     * 2.4 GHz channels sit 5 MHz apart but a 20 MHz-wide channel spans ~±2, so
     * two channels interfere unless their centres are ≥ 5 apart — which is
     * exactly why 1/6/11 are clear of each other. A nearby AP therefore adds to
     * the congestion of any candidate channel within this many steps of it.
     */
    private const val OVERLAP_RADIUS = 4

    /** Band display order: real bands ascending, then the unknown bucket last. */
    private val bandOrder = listOf(BAND_2_4, "5 GHz", "6 GHz")

    /** Occupancy of a single (band, channel) bucket. */
    data class ChannelOccupancy(val band: String, val channel: Int, val count: Int)

    /**
     * A channel-congestion read of a nearby-network list.
     *
     * - [occupancy] — every observed (band, channel) bucket with its count,
     *   ordered by band then channel, for a per-channel display.
     * - [leastCongested2_4] — the non-overlapping 2.4 GHz channel(s) with the
     *   lowest overlap-weighted occupancy. A tie lists all winners; empty when
     *   no 2.4 GHz networks were seen (so the UI can hide the recommendation
     *   honestly rather than claim "ch 1" from no data).
     * - [overlapCounts2_4] — overlap-weighted occupancy for each of 1/6/11,
     *   the basis for [leastCongested2_4]. The analyser's move suggestion
     *   ([suggestLessCongestedChannel]) applies the same overlap model.
     */
    data class Summary(
        val occupancy: List<ChannelOccupancy>,
        val leastCongested2_4: List<Int>,
        val overlapCounts2_4: Map<Int, Int>,
    ) {
        /** True when there is nothing to show — no networks bucketed at all. */
        val isEmpty: Boolean get() = occupancy.isEmpty()
    }

    /**
     * Bucket [nearby] by band + channel and derive the 2.4 GHz least-congested
     * recommendation. Channel 0 (unknown frequency) and the unknown band still
     * count toward [Summary.occupancy] honestly, but only real 2.4 GHz entries
     * feed the overlap maths.
     */
    fun summarise(nearby: List<LocalScanResult.NearbyNetwork>): Summary {
        val occupancy = nearby
            .groupingBy { it.band to it.channel }
            .eachCount()
            .map { (key, count) -> ChannelOccupancy(key.first, key.second, count) }
            .sortedWith(
                compareBy({ bandRank(it.band) }, { it.band }, { it.channel }),
            )

        val channels2_4 = overlappable2_4Channels(nearby)
        val overlapCounts = if (channels2_4.isEmpty()) emptyMap() else overlapCounts(channels2_4)
        val leastCongested = overlapCounts.minOfOrNull { it.value }?.let { min ->
            NON_OVERLAPPING_2_4.filter { overlapCounts[it] == min }
        } ?: emptyList()

        return Summary(occupancy, leastCongested, overlapCounts)
    }

    /**
     * How congested each of the non-overlapping channels is *relative to where a
     * connected 2.4 GHz AP sits*, when a clearly-emptier channel exists. Returns
     * null unless the AP is on the 2.4 GHz band, its channel is genuinely
     * congested, and some 1/6/11 channel is emptier by at least [margin] — the
     * honest bar for "worth retuning". The AP itself is not in [nearby] (the
     * scanner excludes the connected BSSID), so counts measure competing APs.
     *
     * [margin] defaults to [DEFAULT_MARGIN]; callers can tighten it.
     */
    fun suggestLessCongestedChannel(
        connectedChannel: Int,
        connectedBand: String,
        nearby: List<LocalScanResult.NearbyNetwork>,
        margin: Int = DEFAULT_MARGIN,
    ): Suggestion? {
        if (connectedBand != BAND_2_4 || connectedChannel <= 0) return null
        val channels2_4 = overlappable2_4Channels(nearby)
        if (channels2_4.isEmpty()) return null

        val connectedOccupancy = channels2_4.count { kotlin.math.abs(it - connectedChannel) <= OVERLAP_RADIUS }
        val overlapCounts = overlapCounts(channels2_4)
        val best = overlapCounts.minByOrNull { it.value } ?: return null
        // Congested where it is, and a non-overlapping channel is clearly emptier.
        if (connectedOccupancy < margin) return null
        if (best.value > connectedOccupancy - margin) return null
        return Suggestion(
            connectedChannel = connectedChannel,
            connectedOccupancy = connectedOccupancy,
            suggestedChannel = best.key,
            suggestedOccupancy = best.value,
        )
    }

    /** A "move to a quieter channel" recommendation for a 2.4 GHz AP. */
    data class Suggestion(
        val connectedChannel: Int,
        val connectedOccupancy: Int,
        val suggestedChannel: Int,
        val suggestedOccupancy: Int,
    )

    /** Minimum occupancy gap before a channel move is worth suggesting. */
    const val DEFAULT_MARGIN = 2

    private fun bandRank(band: String): Int =
        bandOrder.indexOf(band).let { if (it < 0) bandOrder.size else it }

    /**
     * The 2.4 GHz channels that can overlap a candidate — real channels only.
     * Channel 0 is the [WifiMapping.frequencyToChannel] "unknown frequency"
     * sentinel; a 2.4 GHz frequency outside the standard channel ranges maps to
     * it, but it has no defined centre so it can't sensibly overlap 1/6/11 and
     * would otherwise skew the pick toward the higher channels. It still counts
     * toward [Summary.occupancy] (grouped separately), just not the overlap maths.
     */
    private fun overlappable2_4Channels(nearby: List<LocalScanResult.NearbyNetwork>): List<Int> =
        nearby.filter { it.band == BAND_2_4 && it.channel > 0 }.map { it.channel }

    /** Overlap-weighted occupancy of each non-overlapping channel over [channels2_4]. */
    private fun overlapCounts(channels2_4: List<Int>): Map<Int, Int> =
        NON_OVERLAPPING_2_4.associateWith { candidate ->
            channels2_4.count { kotlin.math.abs(it - candidate) <= OVERLAP_RADIUS }
        }
}
