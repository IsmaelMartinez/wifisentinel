package io.github.ismaelmartinez.wifisentinel.scan

/**
 * Pure, framework-free duplicate-SSID / possible-evil-twin read of an RF
 * neighbourhood — the security counterpart to [ChannelCongestion]'s
 * performance read. Extracted (like [WifiMapping] / [HostMerge] /
 * [ScanPresentation]) so the grouping and mismatch logic can be
 * JVM-unit-tested without a device. See docs/android-companion.md §9.
 *
 * It groups [LocalScanResult.NearbyNetwork]s by SSID, surfaces SSIDs
 * advertised by more than one BSSID, and flags the honest-to-detect
 * anomalies:
 *
 * - the same SSID appearing with *mismatched security* (e.g. one WPA2 and
 *   one Open BSSID) — [DuplicateSsid.mixedSecurity];
 * - a nearby BSSID sharing the *connected* SSID on mismatched security —
 *   [mismatchedTwins]. A [Mismatch.WEAKER] twin is the classic evil-twin
 *   shape; a [Mismatch.STRONGER] twin means the phone itself is on the
 *   weaker side of a duplicated SSID — the vantage point of a device that
 *   has already joined the twin.
 *
 * False-positive guard: a single SSID on multiple BSSIDs is normal
 * (mesh systems, multi-AP roaming, band-specific radios), so multi-BSSID
 * alone is never treated as an anomaly — only a security mismatch is the
 * signal. The taxonomy deliberately mirrors the CLI's
 * `src/analyser/rf/rogue-ap.ts` + `src/collector/schema/security.ts`
 * (`isWeakerSecurity`): strength compares by protocol family, and an
 * "unknown" label on either side is never comparable — we refuse to claim
 * a downgrade we can't measure. The phone's coarse labels carry no
 * Personal/Enterprise mode, so the CLI's mode-downgrade rule has no
 * phone-side equivalent.
 *
 * Coverage caveat (shared with every consumer of the nearby list): the
 * scanner keeps only the [WifiMapping.NEARBY_NETWORKS_CAP] strongest
 * sightings, so in a very dense environment a faint twin can be dropped
 * before this helper ever sees it — absence of a finding is not proof of
 * absence.
 *
 * Returns typed descriptors only; all UI copy stays in `strings.xml`.
 */
object SsidAnomalies {

    /**
     * Protocol-family strength for the labels
     * [WifiMapping.securityFromCapabilities] emits, ordered weakest to
     * strongest — the same rungs and relative order as the CLI's
     * `FAMILY_STRENGTH` in `src/collector/schema/security.ts`. Mixed-mode
     * labels rank below the pure newer protocol because the older handshake
     * stays negotiable. Null for "unknown": not comparable, never assumed
     * weakest. `SsidAnomaliesTest` anchors this map against the labels the
     * producer actually emits, so a new label can't silently fall off the
     * ladder.
     */
    private val securityStrength = mapOf(
        "OPEN" to 0,
        "WEP" to 1,
        "ENHANCED OPEN" to 2,
        "WPA" to 3,
        "WPA/WPA2" to 4,
        "WPA2" to 5,
        "WPA2/WPA3" to 6,
        "WPA3" to 7,
    )

    private fun strength(security: String): Int? = securityStrength[security.trim().uppercase()]

    /**
     * Whether two labels describe genuinely different security, mirroring the
     * CLI's `securityChanged` in `src/collector/schema/security.ts` at the
     * granularity the phone can support: protocol family only (each rung of
     * the ladder is one family), with an unrecognised/"unknown" label on
     * either side never a change — an unmeasured reading must not manufacture
     * a "security changed" signal. The CLI's extra mode rule (Personal vs
     * Enterprise, counted only when both sides state one) is vacuous here:
     * the phone's coarse labels never carry a mode, so family equality is the
     * whole comparison. Lives on this object so [RfDiff] shares the one
     * Kotlin copy of the ladder.
     */
    fun securityChanged(a: String, b: String): Boolean {
        val fa = strength(a) ?: return false
        val fb = strength(b) ?: return false
        return fa != fb
    }

    /**
     * An SSID advertised by more than one BSSID.
     *
     * - [securities] — the distinct security labels seen across those BSSIDs,
     *   weakest first (unrecognised labels last), for display.
     * - [mixedSecurity] — true only when more than one *comparable* security
     *   family was seen; a fleet of same-security APs (mesh/roaming) is
     *   normal and unflagged, and "unknown" labels never create a mismatch.
     */
    data class DuplicateSsid(
        val ssid: String,
        val bssidCount: Int,
        val securities: List<String>,
        val mixedSecurity: Boolean,
    )

    /** How a twin's security compares to the connected link's. */
    enum class Mismatch { WEAKER, STRONGER }

    /**
     * A nearby BSSID advertising the connected SSID with genuinely
     * mismatched security, and which side of the mismatch it sits on.
     */
    data class MismatchedTwin(
        val network: LocalScanResult.NearbyNetwork,
        val mismatch: Mismatch,
    )

    /**
     * Group [nearby] — plus the [connected] AP itself, when one is present —
     * by SSID and return the SSIDs seen on more than one BSSID,
     * mixed-security entries first, then by BSSID count descending, then by
     * SSID for a stable order.
     *
     * The connected AP is included because [WifiMapping.mapNearbyNetworks]
     * excludes its BSSID from the nearby list: without it, the joined SSID's
     * one nearby twin would read as a single-BSSID (hence hidden) group and
     * a mesh of N+1 members would count N. It only joins the grouping when
     * its BSSID is known (a redacted BSSID could not have been excluded from
     * [nearby], so adding it back would double-count) and its SSID is
     * non-blank. Hidden and blank SSIDs are skipped — distinct networks
     * without a usable name are indistinguishable, so grouping them would
     * fabricate a multi-BSSID SSID that may not exist. The nearby list is
     * already deduped by BSSID, so group size is the BSSID count.
     */
    fun duplicates(
        nearby: List<LocalScanResult.NearbyNetwork>,
        connected: LocalScanResult.Wifi? = null,
    ): List<DuplicateSsid> {
        val connectedEntry = connected?.takeIf {
            !it.ssid.isNullOrBlank() && it.bssid != null
        }?.let {
            LocalScanResult.NearbyNetwork(
                ssid = it.ssid,
                bssid = it.bssid!!,
                security = it.security,
                channel = it.channel,
                band = it.band,
                signal = it.signal,
            )
        }
        return (nearby + listOfNotNull(connectedEntry))
            .filter { !it.ssid.isNullOrBlank() }
            .groupBy { it.ssid!! }
            .filterValues { it.size > 1 }
            .map { (ssid, networks) ->
                val securities = networks
                    .map { it.security }
                    .distinct()
                    .sortedWith(compareBy(nullsLast(naturalOrder())) { strength(it) })
                val comparableFamilies = securities.mapNotNull { strength(it) }.distinct()
                DuplicateSsid(
                    ssid = ssid,
                    bssidCount = networks.size,
                    securities = securities,
                    mixedSecurity = comparableFamilies.size > 1,
                )
            }
            .sortedWith(
                compareByDescending<DuplicateSsid> { it.mixedSecurity }
                    .thenByDescending { it.bssidCount }
                    .thenBy { it.ssid },
            )
    }

    /**
     * Nearby BSSIDs advertising the connected SSID on mismatched security,
     * strongest signal first (the loudest suspect is the one a phone would
     * roam to). [Mismatch.WEAKER] twins are the evil-twin shape;
     * [Mismatch.STRONGER] twins mean the joined link itself is the weaker
     * side — the state a phone that already auto-joined an open twin is in,
     * where the legitimate AP is the one broadcasting stronger security.
     * Empty when there is nothing honest to flag:
     *
     * - no usable connected SSID (survey mode / hidden or blank SSID) —
     *   nothing to compare;
     * - either side's security is unrecognised — not comparable, no claim;
     * - the twin's security is the same family — same-security co-channel
     *   BSSIDs are ordinary mesh/roaming infrastructure, not a signal.
     *
     * The connected BSSID itself is never in [nearby]
     * ([WifiMapping.mapNearbyNetworks] excludes it), so every match here is
     * genuinely another radio.
     */
    fun mismatchedTwins(
        connectedSsid: String?,
        connectedSecurity: String,
        nearby: List<LocalScanResult.NearbyNetwork>,
    ): List<MismatchedTwin> {
        if (connectedSsid.isNullOrBlank()) return emptyList()
        val connectedStrength = strength(connectedSecurity) ?: return emptyList()
        return nearby
            .filter { it.ssid == connectedSsid }
            .mapNotNull { twin ->
                val twinStrength = strength(twin.security) ?: return@mapNotNull null
                when {
                    twinStrength < connectedStrength -> MismatchedTwin(twin, Mismatch.WEAKER)
                    twinStrength > connectedStrength -> MismatchedTwin(twin, Mismatch.STRONGER)
                    else -> null
                }
            }
            .sortedByDescending { it.network.signal }
    }
}
