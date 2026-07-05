package io.github.ismaelmartinez.wifisentinel.store

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented Room test: exercises [ScanDao] against a real on-device
 * SQLite database (in-memory, so nothing leaks between runs). Complements
 * the JVM tests, which cannot touch Room's SQLite layer.
 */
@RunWith(AndroidJUnit4::class)
class ScanDaoTest {

    private lateinit var db: ScanDatabase
    private lateinit var dao: ScanDao

    @Before
    fun createDb() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        db = Room.inMemoryDatabaseBuilder(context, ScanDatabase::class.java).build()
        dao = db.scanDao()
    }

    @After
    fun closeDb() {
        db.close()
    }

    private fun entity(scanId: String, timestamp: String, json: String = """{"id":"$scanId"}""") =
        ScanEntity(
            scanId = scanId,
            timestamp = timestamp,
            ssid = "HomeNet",
            overallRisk = "LOW",
            json = json,
        )

    @Test
    fun insertThenQueryRoundTrips() = runBlocking {
        dao.upsert(entity("older", "2026-07-01T10:00:00Z"))
        dao.upsert(entity("newer", "2026-07-02T10:00:00Z"))

        val summaries = dao.observeSummaries().first()
        // Newest first, denormalised columns intact.
        assertEquals(listOf("newer", "older"), summaries.map { it.scanId })
        assertEquals("HomeNet", summaries.first().ssid)
        assertEquals("LOW", summaries.first().overallRisk)

        assertEquals("""{"id":"older"}""", dao.findJson("older"))
        assertNull(dao.findJson("missing"))
    }

    @Test
    fun upsertReplacesRowWithSameScanId() = runBlocking {
        dao.upsert(entity("scan", "2026-07-01T10:00:00Z", json = """{"v":1}"""))
        dao.upsert(entity("scan", "2026-07-01T10:00:00Z", json = """{"v":2}"""))

        assertEquals(1, dao.observeSummaries().first().size)
        assertEquals("""{"v":2}""", dao.findJson("scan"))
    }

    @Test
    fun clearEmptiesTheTable() = runBlocking {
        dao.upsert(entity("scan", "2026-07-01T10:00:00Z"))
        dao.clear()
        assertEquals(emptyList<ScanSummary>(), dao.observeSummaries().first())
    }
}
