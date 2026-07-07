package io.github.ismaelmartinez.wifisentinel.scan

/**
 * Pure, framework-free presentation helpers for a [LocalScanResult] — the
 * decisions the Compose UI needs about how to *describe* a scan, extracted so
 * they can be JVM-unit-tested without Compose or an emulator (same rationale as
 * [WifiMapping] / [HostMerge]). They return typed descriptors the UI maps onto
 * string resources, so all copy / translation stays in `strings.xml`.
 */
object ScanPresentation {

    /**
     * How a scan should be titled in the history list and the detail bar.
     *
     * - [Named] — an identified connected AP; show its SSID.
     * - [Survey] — a nearby-only survey: no associated network, but the RF
     *   neighbourhood was captured. Show it as a survey (with the count) rather
     *   than a blank "unknown network".
     * - [Unnamed] — no network name and nothing surveyed (e.g. a scan with no
     *   permission, or a hidden AP with no nearby list).
     */
    sealed interface Title {
        data class Named(val ssid: String) : Title
        data class Survey(val nearbyCount: Int) : Title
        data object Unnamed : Title
    }

    /**
     * True when the scan has no associated-AP section — a disconnected or
     * redacted read (or a deliberate survey). The connected-AP section is the
     * only thing that carries an association, so its absence is the signal.
     */
    fun isNearbyOnly(wifi: LocalScanResult.Wifi?): Boolean = wifi == null

    /**
     * Title descriptor for a history row / detail bar. Prefers the connected
     * SSID; failing that, a captured RF neighbourhood marks the scan as a
     * survey so it reads honestly. `ssid` and `nearbyCount` come straight off
     * the stored summary, so no full result needs deserialising.
     */
    fun title(ssid: String?, nearbyCount: Int?): Title = when {
        !ssid.isNullOrBlank() -> Title.Named(ssid)
        (nearbyCount ?: 0) > 0 -> Title.Survey(nearbyCount!!)
        else -> Title.Unnamed
    }
}
