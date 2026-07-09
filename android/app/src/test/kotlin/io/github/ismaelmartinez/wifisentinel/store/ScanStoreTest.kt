package io.github.ismaelmartinez.wifisentinel.store

import io.github.ismaelmartinez.wifisentinel.scan.LocalScanResult
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Pure-JVM tests for [ScanStore.loadPreviousWithNearby] — the predecessor
 * selection behind the since-last-scan RF diff — against a fake in-memory
 * [ScanDao] (the interface has no Android dependency, so no Room/emulator is
 * needed; [ScanDaoTest] covers the real SQL). The point under test is the
 * *chronology* contract: the pick is made on parsed instants, not timestamp
 * strings, because `Instant.toString()` omits the fraction on whole-second
 * instants and lexicographic order then disagrees with real time order.
 */
class ScanStoreTest {

    private class FakeDao : ScanDao {
        val rows = mutableMapOf<String, ScanEntity>()

        override suspend fun upsert(scan: ScanEntity) {
            rows[scan.scanId] = scan
        }

        override fun observeSummaries(): Flow<List<ScanSummary>> = flowOf(emptyList())

        override suspend fun findJson(scanId: String): String? = rows[scanId]?.json

        override suspend fun nearbySummariesExcept(scanId: String): List<ScanSummary> =
            rows.values
                .filter { it.nearbyCount != null && it.scanId != scanId }
                .map {
                    ScanSummary(
                        scanId = it.scanId,
                        timestamp = it.timestamp,
                        ssid = it.ssid,
                        overallRisk = it.overallRisk,
                        nearbyCount = it.nearbyCount,
                    )
                }

        override suspend fun clear() = rows.clear()
    }

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private fun scan(
        scanId: String,
        timestamp: String,
        nearby: List<LocalScanResult.NearbyNetwork>? = emptyList(),
    ) = LocalScanResult(
        meta = LocalScanResult.Meta(scanId = scanId, timestamp = timestamp, appVersion = "test"),
        wifi = null,
        nearbyNetworks = nearby,
        network = null,
    )

    private fun daoWith(vararg stored: LocalScanResult): FakeDao {
        val dao = FakeDao()
        for (result in stored) {
            dao.rows[result.meta.scanId] = ScanEntity(
                scanId = result.meta.scanId,
                timestamp = result.meta.timestamp,
                ssid = result.wifi?.ssid,
                overallRisk = null,
                nearbyCount = result.nearbyNetworks?.size,
                json = json.encodeToString(result),
            )
        }
        return dao
    }

    private fun store(vararg stored: LocalScanResult): ScanStore =
        ScanStore(daoWith(*stored), json)

    @Test
    fun picksTheChronologicallyLatestPriorScan() = runBlocking {
        val store = store(
            scan("oldest", "2026-07-01T10:00:00.100Z"),
            scan("middle", "2026-07-02T10:00:00.100Z"),
            scan("viewed", "2026-07-03T10:00:00.100Z"),
            scan("newer", "2026-07-04T10:00:00.100Z"),
        )
        val previous = store.loadPreviousWithNearby(scan("viewed", "2026-07-03T10:00:00.100Z"))
        assertEquals("middle", previous?.meta?.scanId)
    }

    @Test
    fun sameSecondPrecisionMismatchDoesNotHideThePredecessor() = runBlocking {
        // "…05Z" (whole-second) sorts lexicographically AFTER "…05.500Z"
        // ('.' < 'Z'), so a string-ordered strictly-before pick would skip
        // this genuine predecessor. Parsed instants must find it.
        val store = store(scan("whole-second", "2026-07-03T10:00:05Z"))
        val previous = store.loadPreviousWithNearby(scan("viewed", "2026-07-03T10:00:05.500Z"))
        assertEquals("whole-second", previous?.meta?.scanId)
    }

    @Test
    fun sameSecondPrecisionMismatchDoesNotPickAFutureScan() = runBlocking {
        // The other direction: viewing the whole-second scan, the fractional
        // same-second scan is chronologically LATER and must not be chosen
        // (string comparison would have called it "before"). With a real
        // earlier scan present, that one wins.
        val store = store(
            scan("later-fractional", "2026-07-03T10:00:05.500Z"),
            scan("real-predecessor", "2026-07-03T09:00:00.100Z"),
        )
        val previous = store.loadPreviousWithNearby(scan("viewed", "2026-07-03T10:00:05Z"))
        assertEquals("real-predecessor", previous?.meta?.scanId)
    }

    @Test
    fun fallsBackPastAnUndecodableNearestCandidate() = runBlocking {
        val dao = daoWith(scan("clean", "2026-07-01T10:00:00.100Z"))
        // A nearer candidate whose blob is corrupt: skipped, not fatal.
        dao.rows["corrupt"] = ScanEntity(
            scanId = "corrupt",
            timestamp = "2026-07-02T10:00:00.100Z",
            ssid = null,
            overallRisk = null,
            nearbyCount = 3,
            json = "{not json",
        )
        val store = ScanStore(dao, json)
        val previous = store.loadPreviousWithNearby(scan("viewed", "2026-07-03T10:00:00.100Z"))
        assertEquals("clean", previous?.meta?.scanId)
    }

    @Test
    fun nullWhenNoPriorScanExists() = runBlocking {
        // Only newer scans, or nothing at all: no predecessor, section hides.
        val store = store(scan("newer", "2026-07-04T10:00:00.100Z"))
        assertNull(store.loadPreviousWithNearby(scan("viewed", "2026-07-03T10:00:00.100Z")))
        assertNull(store().loadPreviousWithNearby(scan("viewed", "2026-07-03T10:00:00.100Z")))
    }

    @Test
    fun unparseableTimestampsAreSkippedNotFatal() = runBlocking {
        val store = store(
            scan("bad-timestamp", "yesterday-ish"),
            scan("good", "2026-07-01T10:00:00.100Z"),
        )
        val previous = store.loadPreviousWithNearby(scan("viewed", "2026-07-03T10:00:00.100Z"))
        assertEquals("good", previous?.meta?.scanId)
        // And a viewed scan whose own timestamp doesn't parse claims nothing.
        assertNull(store.loadPreviousWithNearby(scan("viewed", "not-a-timestamp")))
    }
}
