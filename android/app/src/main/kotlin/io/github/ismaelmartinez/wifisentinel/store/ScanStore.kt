package io.github.ismaelmartinez.wifisentinel.store

import android.content.Context
import androidx.room.Room
import io.github.ismaelmartinez.wifisentinel.scan.LocalScanResult
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.time.Instant

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
                    // Denormalised so a nearby-only survey (ssid null) still
                    // shows its RF density in history without loading the blob.
                    nearbyCount = result.nearbyNetworks?.size,
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

    /**
     * The most recent stored scan strictly before [result] that collected a
     * nearby list, or null when no comparable predecessor exists (first ever
     * scan, or a history of pre-upgrade rows with no RF capture). Backs the
     * since-last-scan RF diff ([io.github.ismaelmartinez.wifisentinel.scan.RfDiff])
     * — a derived view, so this only reads; nothing new is stored.
     *
     * Chronology is decided on *parsed* instants, not timestamp strings:
     * `Instant.toString()` omits the fraction on a whole-second instant, and
     * "…05.500Z" sorts lexicographically before "…05Z" despite being later,
     * so a string-ordered SQL pick could skip a real predecessor or diff
     * against a chronologically *newer* scan (see [ScanDao.nearbySummariesExcept]).
     * Rows whose timestamp doesn't parse are skipped — no honest "before"
     * claim can be made for them. Candidates are tried newest-first, falling
     * back past a row whose blob fails to decode into a diffable scan
     * (mirroring [load]'s best-effort stance) rather than hiding the section
     * because the nearest row is corrupt. Decoding runs off the caller's
     * dispatcher — the UI calls this from a main-thread coroutine.
     */
    suspend fun loadPreviousWithNearby(result: LocalScanResult): LocalScanResult? {
        val reference = parseInstant(result.meta.timestamp) ?: return null
        val candidates = dao.nearbySummariesExcept(result.meta.scanId)
            .mapNotNull { summary ->
                parseInstant(summary.timestamp)
                    ?.takeIf { it < reference }
                    ?.let { instant -> instant to summary.scanId }
            }
            .sortedByDescending { it.first }
        return withContext(Dispatchers.Default) {
            candidates.firstNotNullOfOrNull { (_, scanId) ->
                dao.findJson(scanId)?.let { blob ->
                    runCatching { json.decodeFromString<LocalScanResult>(blob) }.getOrNull()
                }?.takeIf { it.nearbyNetworks != null }
            }
        }
    }

    private fun parseInstant(timestamp: String): Instant? =
        runCatching { Instant.parse(timestamp) }.getOrNull()

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
            ).addMigrations(MIGRATION_1_2).build()
            return ScanStore(db.scanDao(), json)
        }
    }
}
