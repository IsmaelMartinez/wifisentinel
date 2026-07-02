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
    @Query("SELECT scanId, timestamp, ssid, overallRisk FROM scans ORDER BY timestamp DESC")
    fun observeSummaries(): Flow<List<ScanSummary>>

    /** The stored JSON blob for one scan, or null if the id is unknown. */
    @Query("SELECT json FROM scans WHERE scanId = :scanId LIMIT 1")
    suspend fun findJson(scanId: String): String?

    @Query("DELETE FROM scans")
    suspend fun clear()
}
