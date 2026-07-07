package io.github.ismaelmartinez.wifisentinel.store

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * One row per completed scan. The full `LocalScanResult` is stored as a
 * serialized kotlinx.serialization JSON blob in [json]; [timestamp], [ssid],
 * [overallRisk], and [nearbyCount] are denormalised copies so the history list
 * can render without deserialising every blob.
 *
 * [timestamp] is the ISO-8601 UTC instant from `meta.timestamp`. It sorts
 * lexicographically, so `ORDER BY timestamp DESC` yields newest-first.
 *
 * [ssid] is null when no AP was joined (a nearby-only survey, or a redacted
 * read); [nearbyCount] then lets the history row show the survey's RF density
 * instead of a blank "unknown network". Null (never zero-defaulted) means the
 * RF list wasn't collected — see `LocalScanResult.nearbyNetworks`.
 */
@Entity(tableName = "scans")
data class ScanEntity(
    @PrimaryKey val scanId: String,
    val timestamp: String,
    val ssid: String?,
    val overallRisk: String?,
    val nearbyCount: Int?,
    val json: String,
)
