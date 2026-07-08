package io.github.ismaelmartinez.wifisentinel.scan

/**
 * Pure, framework-free since-last-scan diff of the RF neighbourhood — the
 * first read that notices the environment *changed* rather than reading one
 * snapshot (every other helper — [ChannelCongestion], [SsidAnomalies] — is
 * single-scan). Extracted (like [WifiMapping] / [HostMerge] /
 * [ScanPresentation]) so the matching logic can be JVM-unit-tested without a
 * device. See docs/android-companion.md §9.
 *
 * It compares two `nearbyNetworks` lists keyed by BSSID (lowercased — same
 * rationale as the CLI's `apKey` in `src/analyser/rf/environment.ts`: BSSIDs
 * are case-insensitive hex and sources disagree on case) and returns typed
 * descriptors for:
 *
 * - APs that **appeared** — with the interesting case flagged specially:
 *   a new BSSID on an SSID the previous scan already knew
 *   ([Appeared.onKnownSsid]), which is a stronger possible-twin signal than
 *   anything a single snapshot can give;
 * - APs that **vanished** — informational colour only, never a warning:
 *   WiFi scans are noisy and a weak AP missing from one scan is normal
 *   (the scanner also keeps only the [WifiMapping.NEARBY_NETWORKS_CAP]
 *   strongest sightings, so an AP can "vanish" by merely slipping below the
 *   cap);
 * - per-BSSID **security changes**, via [SsidAnomalies.securityChanged] —
 *   family-level, mirroring the CLI's `securityChanged` semantics in
 *   `src/collector/schema/security.ts`, so an "unknown" label on either side
 *   is never a change.
 *
 * The connected AP of each scan (excluded from its own nearby list by
 * construction — [WifiMapping.mapNearbyNetworks]) is folded back into that
 * scan's side of the comparison when its BSSID is known. Without the fold, a
 * phone that merely roamed between scans would report its previous AP as
 * "appeared": the old BSSID was hidden from the previous list but shows in
 * the current one. A redacted (null) BSSID cannot be folded — it could not
 * have been excluded from the nearby list either, so adding it back could
 * double-count a radio.
 *
 * This is a *derived*, presentation-layer view: computed on display from two
 * stored scans, never stored or exported (the CLI import recomputes analysis
 * from single-scan fields, so nothing history-dependent may leak into the
 * export contract — see docs/android-companion.md §9). The CLI's own
 * change taxonomy lives in `src/store/diff.ts` and `rf --compare`
 * (`src/analyser/rf/environment.ts`); this helper keeps the phone's subset
 * consistent with it. Returns typed descriptors only; UI copy stays in
 * `strings.xml`.
 */
object RfDiff {

    /**
     * A BSSID present now but not in the previous scan. [onKnownSsid] marks
     * the signal case: the SSID itself was already in the previous scan
     * (nearby or connected), so this is a *new radio on a known network* —
     * the shape of a twin being stood up. A plain appearance (new SSID
     * entirely, or a hidden/blank SSID that can't be matched by name) is
     * ordinary neighbourhood churn.
     */
    data class Appeared(
        val network: LocalScanResult.NearbyNetwork,
        val onKnownSsid: Boolean,
    )

    /**
     * A matched BSSID whose security family genuinely changed between scans.
     * [network] is the current sighting; [previousSecurity] the label the
     * previous scan recorded.
     */
    data class SecurityChange(
        val network: LocalScanResult.NearbyNetwork,
        val previousSecurity: String,
    )

    /**
     * The full diff. [appeared] sorts known-SSID appearances first, then
     * strongest signal; [vanished] and [securityChanges] sort strongest
     * first (of the sighting each carries).
     */
    data class Diff(
        val appeared: List<Appeared>,
        val vanished: List<LocalScanResult.NearbyNetwork>,
        val securityChanges: List<SecurityChange>,
    ) {
        val isEmpty: Boolean
            get() = appeared.isEmpty() && vanished.isEmpty() && securityChanges.isEmpty()
    }

    /** The connected AP as a nearby-shaped entry, or null when unfoldable. */
    private fun asNearby(connected: LocalScanResult.Wifi?): LocalScanResult.NearbyNetwork? =
        connected?.bssid?.let { bssid ->
            LocalScanResult.NearbyNetwork(
                ssid = connected.ssid,
                bssid = bssid,
                security = connected.security,
                channel = connected.channel,
                band = connected.band,
                signal = connected.signal,
            )
        }

    /**
     * Compare the previous scan's neighbourhood against the current one.
     * Each side is its nearby list plus its own connected AP (when foldable —
     * see the object doc). On the (defensive) chance of a BSSID collision
     * between a nearby entry and the folded connected AP, the connected
     * reading wins — it is the fresher observation of that radio.
     */
    fun diff(
        previousNearby: List<LocalScanResult.NearbyNetwork>,
        currentNearby: List<LocalScanResult.NearbyNetwork>,
        previousConnected: LocalScanResult.Wifi? = null,
        currentConnected: LocalScanResult.Wifi? = null,
    ): Diff {
        val previous = (previousNearby + listOfNotNull(asNearby(previousConnected)))
            .associateBy { it.bssid.lowercase() }
        val current = (currentNearby + listOfNotNull(asNearby(currentConnected)))
            .associateBy { it.bssid.lowercase() }

        // SSIDs the previous scan knew, for the new-BSSID-on-known-SSID flag.
        // Hidden/blank SSIDs are excluded: distinct networks without a usable
        // name are indistinguishable, so a name match would be fabricated
        // (same rationale as SsidAnomalies' grouping).
        val previousSsids = previous.values
            .mapNotNull { it.ssid?.takeIf(String::isNotBlank) }
            .toSet()

        val appeared = current.values
            .filter { it.bssid.lowercase() !in previous }
            .map { network ->
                val name = network.ssid?.takeIf(String::isNotBlank)
                Appeared(
                    network = network,
                    onKnownSsid = name != null && name in previousSsids,
                )
            }
            .sortedWith(
                compareByDescending<Appeared> { it.onKnownSsid }
                    .thenByDescending { it.network.signal },
            )

        val vanished = previous.values
            .filter { it.bssid.lowercase() !in current }
            .sortedByDescending { it.signal }

        val securityChanges = current.values
            .mapNotNull { network ->
                val before = previous[network.bssid.lowercase()] ?: return@mapNotNull null
                if (SsidAnomalies.securityChanged(before.security, network.security)) {
                    SecurityChange(network = network, previousSecurity = before.security)
                } else {
                    null
                }
            }
            .sortedByDescending { it.network.signal }

        return Diff(appeared = appeared, vanished = vanished, securityChanges = securityChanges)
    }
}
