package io.github.ismaelmartinez.wifisentinel.store

/**
 * Lightweight projection for the history list — the JSON blob is deliberately
 * excluded so the list query stays cheap. Room maps the selected columns onto
 * this POJO by name.
 */
data class ScanSummary(
    val scanId: String,
    val timestamp: String,
    val ssid: String?,
    val overallRisk: String?,
    val nearbyCount: Int?,
)
