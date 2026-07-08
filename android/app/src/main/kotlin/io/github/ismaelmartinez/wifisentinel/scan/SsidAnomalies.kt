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
 * - a nearby BSSID sharing the *connected* SSID on weaker/open security
 *   than the joined link — [weakerTwins], the classic evil-twin shape.
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
 * Returns typed descriptors only; all UI copy stays in `strings.xml`.
 */
object SsidAnomalies {

    /**
     * Protocol-family strength for the coarse labels
     * [WifiMapping.securityFromCapabilities] emits, ordered weakest to
     * strongest — the same ordering as the CLI's `FAMILY_STRENGTH` in
     * `src/collector/schema/security.ts` (the phone never emits the mixed
     * "WPA/WPA2"-style labels, so those rungs are simply absent). Null for
     * "unknown": not comparable, never assumed weakest.
     */
    private val securityStrength = mapOf(
        "OPEN" to 0,
        "WEP" to 1,
        "ENHANCED OPEN" to 2,
        "WPA" to 3,
        "WPA2" to 4,
        "WPA3" to 5,
    )

    private fun strength(security: String): Int? = securityStrength[security.trim().uppercase()]

    /**
     * An SSID advertised by more than one nearby BSSID.
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

    /**
     * A nearby BSSID advertising [ssid] with genuinely weaker security than
     * the link the phone is joined to. Carries the fields the analyser's
     * finding needs to describe the suspect AP.
     */
    data class WeakerTwin(
        val ssid: String,
        val bssid: String,
        val security: String,
        val channel: Int,
        val band: String,
        val signal: Int,
    )

    /**
     * Group [nearby] by SSID and return the SSIDs seen on more than one
     * BSSID, mixed-security entries first, then by BSSID count descending,
     * then by SSID for a stable order. Hidden networks (null SSID) are
     * skipped — distinct hidden networks are indistinguishable, so grouping
     * them would fabricate a multi-BSSID SSID that may not exist. The nearby
     * list is already deduped by BSSID ([WifiMapping.mapNearbyNetworks]), so
     * group size is the BSSID count.
     */
    fun duplicates(nearby: List<LocalScanResult.NearbyNetwork>): List<DuplicateSsid> =
        nearby
            .filter { it.ssid != null }
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

    /**
     * Nearby BSSIDs advertising the connected SSID on strictly weaker
     * security than the joined link, strongest signal first (the loudest
     * suspect is the one a phone would roam to). Empty when there is nothing
     * honest to flag:
     *
     * - no connected SSID (survey mode / hidden SSID) — nothing to compare;
     * - either side's security is unrecognised — not comparable, no claim;
     * - the twin's security is equal or stronger — same-security co-channel
     *   BSSIDs are ordinary mesh/roaming infrastructure, not a signal.
     *
     * The connected BSSID itself is never in [nearby]
     * ([WifiMapping.mapNearbyNetworks] excludes it), so every match here is
     * genuinely another radio.
     */
    fun weakerTwins(
        connectedSsid: String?,
        connectedSecurity: String,
        nearby: List<LocalScanResult.NearbyNetwork>,
    ): List<WeakerTwin> {
        if (connectedSsid == null) return emptyList()
        val connectedStrength = strength(connectedSecurity) ?: return emptyList()
        return nearby
            .filter { it.ssid == connectedSsid }
            .filter { twin ->
                val twinStrength = strength(twin.security)
                twinStrength != null && twinStrength < connectedStrength
            }
            .sortedByDescending { it.signal }
            .map {
                WeakerTwin(
                    ssid = connectedSsid,
                    bssid = it.bssid,
                    security = it.security,
                    channel = it.channel,
                    band = it.band,
                    signal = it.signal,
                )
            }
    }
}
