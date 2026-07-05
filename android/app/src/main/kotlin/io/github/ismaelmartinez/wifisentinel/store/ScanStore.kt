package io.github.ismaelmartinez.wifisentinel.store

import android.content.Context
import androidx.room.Room
import io.github.ismaelmartinez.wifisentinel.scan.LocalScanResult
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.Flow
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * Persists completed scans to a single-table Room database and exposes the
 * history as a reactive [Flow]. The database file lives in app-private storage
 * and is excluded from auto-backup (`allowBackup=false` plus explicit backup
 * rules) — see docs/android-companion.md §7.
 */
class ScanStore internal constructor(
    private val dao: ScanDao,
    private val json: Json,
) {
    /** Newest-first stream of scan summaries for the history list. */
    fun history(): Flow<List<ScanSummary>> = dao.observeSummaries()

    /**
     * Persist a completed scan, replacing any existing row with the same id.
     * Best-effort, mirroring [load]: a failed write (e.g. disk full) means the
     * scan is missing from history, not that the app crashes — the caller is
     * still holding the result to display.
     */
    suspend fun save(result: LocalScanResult) {
        try {
            dao.upsert(
                ScanEntity(
                    scanId = result.meta.scanId,
                    timestamp = result.meta.timestamp,
                    ssid = result.wifi?.ssid,
                    overallRisk = result.analysis?.overallRisk?.name,
                    json = json.encodeToString(result),
                ),
            )
        } catch (e: CancellationException) {
            // Not a storage failure — cancellation must keep propagating.
            throw e
        } catch (_: Exception) {
            // Best-effort: the scan simply won't appear in history.
        }
    }

    /** Re-hydrate a stored scan by id, or null if it is missing / unparseable. */
    suspend fun load(scanId: String): LocalScanResult? {
        val blob = dao.findJson(scanId) ?: return null
        return runCatching { json.decodeFromString<LocalScanResult>(blob) }.getOrNull()
    }

    /** Delete every stored scan. */
    suspend fun clear() = dao.clear()

    companion object {
        private const val DB_NAME = "wifisentinel-scans.db"

        @Volatile
        private var instance: ScanStore? = null

        private val json = Json {
            ignoreUnknownKeys = true
            encodeDefaults = true
        }

        /** Process-wide singleton so the Room connection is shared app-wide. */
        fun get(context: Context): ScanStore =
            instance ?: synchronized(this) {
                instance ?: build(context).also { instance = it }
            }

        private fun build(context: Context): ScanStore {
            val db = Room.databaseBuilder(
                context.applicationContext,
                ScanDatabase::class.java,
                DB_NAME,
            ).build()
            return ScanStore(db.scanDao(), json)
        }
    }
}
