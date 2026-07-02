package io.github.ismaelmartinez.wifisentinel.store

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * One row per completed scan. The full `LocalScanResult` is stored as a
 * serialized kotlinx.serialization JSON blob in [json]; [timestamp], [ssid],
 * and [overallRisk] are denormalised copies so the history list can render
 * without deserialising every blob.
 *
 * [timestamp] is the ISO-8601 UTC instant from `meta.timestamp`. It sorts
 * lexicographically, so `ORDER BY timestamp DESC` yields newest-first.
 */
@Entity(tableName = "scans")
data class ScanEntity(
    @PrimaryKey val scanId: String,
    val timestamp: String,
    val ssid: String?,
    val overallRisk: String?,
    val json: String,
)
