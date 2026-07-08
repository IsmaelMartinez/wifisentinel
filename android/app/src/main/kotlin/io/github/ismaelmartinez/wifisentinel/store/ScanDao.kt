package io.github.ismaelmartinez.wifisentinel.store

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface ScanDao {
    /** Insert a scan, replacing any existing row with the same `scanId`. */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(scan: ScanEntity)

    /** Newest-first stream of summaries; emits again whenever the table changes. */
    @Query("SELECT scanId, timestamp, ssid, overallRisk, nearbyCount FROM scans ORDER BY timestamp DESC")
    fun observeSummaries(): Flow<List<ScanSummary>>

    /** The stored JSON blob for one scan, or null if the id is unknown. */
    @Query("SELECT json FROM scans WHERE scanId = :scanId LIMIT 1")
    suspend fun findJson(scanId: String): String?

    /**
     * The JSON blob of the most recent scan strictly before [timestamp] that
     * collected a nearby list (`nearbyCount IS NOT NULL` — "not collected"
     * rows, including pre-upgrade ones, can't be diffed against). The
     * [scanId] guard excludes the scan being compared itself, so an
     * equal-timestamp self-row never becomes its own predecessor. Backs the
     * since-last-scan RF diff; timestamps are ISO-8601 UTC, so string
     * ordering is chronological (same reason `observeSummaries` can ORDER BY
     * it).
     */
    @Query(
        "SELECT json FROM scans WHERE nearbyCount IS NOT NULL " +
            "AND scanId != :scanId AND timestamp < :timestamp " +
            "ORDER BY timestamp DESC LIMIT 1",
    )
    suspend fun findLatestNearbyJsonBefore(timestamp: String, scanId: String): String?

    @Query("DELETE FROM scans")
    suspend fun clear()
}
