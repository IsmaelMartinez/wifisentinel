package io.github.ismaelmartinez.wifisentinel.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Pure-JVM tests for [SpeedMapping], the throughput maths extracted from
 * [SpeedProbe]. No Android framework types are touched, so these run under
 * `./gradlew test` without an emulator. See docs/android-companion.md §9.
 */
class SpeedMappingTest {

    // ---- bytes + duration → Mbps ---------------------------------------------

    @Test
    fun computesMegabitsPerSecond() {
        // 1,250,000 bytes = 10,000,000 bits; over 1 s that is exactly 10 Mbps.
        assertEquals(10.0, SpeedMapping.downloadMbps(1_250_000, 1_000)!!, 0.0)
    }

    @Test
    fun scalesWithDuration() {
        // Same payload in half the time doubles the rate.
        assertEquals(20.0, SpeedMapping.downloadMbps(1_250_000, 500)!!, 0.0)
    }

    @Test
    fun roundsToTwoDecimalPlaces() {
        // 333,333 bytes over 1 s = 2.666664 Mbps → 2.67.
        assertEquals(2.67, SpeedMapping.downloadMbps(333_333, 1_000)!!, 0.0)
    }

    @Test
    fun handlesLargeTransfersWithoutOverflow() {
        // 25 MB in 2 s = 104.86 Mbps — the fixed-size fetch on a fast link.
        assertEquals(104.86, SpeedMapping.downloadMbps(26_214_400, 2_000)!!, 0.0)
    }

    @Test
    fun emptyMeasurementIsNull() {
        assertNull(SpeedMapping.downloadMbps(0, 1_000))
        assertNull(SpeedMapping.downloadMbps(-1, 1_000))
        assertNull(SpeedMapping.downloadMbps(1_250_000, 0))
        assertNull(SpeedMapping.downloadMbps(1_250_000, -5))
    }

    // ---- full download record -------------------------------------------------

    @Test
    fun assemblesDownloadRecord() {
        val download = SpeedMapping.downloadResult(
            bytesTransferred = 1_250_000,
            durationMs = 1_000,
            testUrl = "https://example.test/blob",
        )!!
        assertEquals(10.0, download.speedMbps, 0.0)
        assertEquals(1_250_000, download.bytesTransferred)
        assertEquals(1_000, download.durationMs)
        assertEquals("https://example.test/blob", download.testUrl)
    }

    @Test
    fun emptyMeasurementYieldsNoRecord() {
        assertNull(SpeedMapping.downloadResult(0, 1_000, "https://example.test/blob"))
    }
}
