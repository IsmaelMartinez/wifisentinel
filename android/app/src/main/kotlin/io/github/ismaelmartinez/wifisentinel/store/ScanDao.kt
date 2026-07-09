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
     * Summaries of every scan that collected a nearby list (`nearbyCount IS
     * NOT NULL` — "not collected" rows, including pre-upgrade ones, can't be
     * diffed against), excluding [scanId] (the scan being compared). Backs
     * the since-last-scan RF diff. Choosing the *most recent prior* scan is
     * deliberately left to the caller: `meta.timestamp` comes from
     * `Instant.toString()`, whose variable sub-second precision ("…05Z" vs
     * "…05.500Z") makes lexicographic string comparison disagree with
     * chronology on same-second boundaries — tolerable for display ordering
     * (`observeSummaries`), not for a correctness-sensitive strictly-before
     * pick. `ScanStore` parses and compares real instants instead.
     */
    @Query(
        "SELECT scanId, timestamp, ssid, overallRisk, nearbyCount FROM scans " +
            "WHERE nearbyCount IS NOT NULL AND scanId != :scanId",
    )
    suspend fun nearbySummariesExcept(scanId: String): List<ScanSummary>

    @Query("DELETE FROM scans")
    suspend fun clear()
}
