package io.github.ismaelmartinez.wifisentinel.scan

import android.os.SystemClock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL

/**
 * Opt-in download throughput probe. Fetches a fixed-size blob from
 * Cloudflare's speed test endpoint and reports the observed throughput via
 * [SpeedMapping]. Bounded twice over: the fetch is a fixed [DEFAULT_TARGET]
 * size (~25 MB) and the read loop aborts after [maxDurationMs], so a slow
 * link can never stream unbounded data. Off by default in the UI to spare
 * mobile data (docs/android-companion.md §3, `speed.download.speedMbps`).
 */
class SpeedProbe {

    /**
     * @return the measured download result, or null if the probe failed
     *   (no connectivity, non-2xx response, timeout before any bytes, …).
     */
    suspend fun measure(
        target: String = DEFAULT_TARGET,
        maxDurationMs: Long = 10_000,
        connectTimeoutMs: Int = 5_000,
    ): LocalScanResult.Speed? = withContext(Dispatchers.IO) {
        var connection: HttpURLConnection? = null
        try {
            connection = (URL(target).openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = connectTimeoutMs
                readTimeout = connectTimeoutMs
                instanceFollowRedirects = false
            }
            if (connection.responseCode !in 200..299) return@withContext null

            // Time from first read to last: throughput of the payload itself,
            // excluding connection setup (the latency probe covers that).
            val start = SystemClock.elapsedRealtime()
            var bytesTransferred = 0L
            val buffer = ByteArray(64 * 1024)
            connection.inputStream.use { stream ->
                while (SystemClock.elapsedRealtime() - start < maxDurationMs) {
                    val read = stream.read(buffer)
                    if (read == -1) break
                    bytesTransferred += read
                }
            }
            val durationMs = SystemClock.elapsedRealtime() - start

            SpeedMapping.downloadResult(bytesTransferred, durationMs, target)
                ?.let { LocalScanResult.Speed(download = it) }
        } catch (_: Exception) {
            null
        } finally {
            connection?.disconnect()
        }
    }

    private companion object {
        /** 25 MB fixed-size fetch — enough to saturate a fast link for a
         *  measurable window without burning through a data plan. */
        const val DEFAULT_TARGET = "https://speed.cloudflare.com/__down?bytes=26214400"
    }
}
