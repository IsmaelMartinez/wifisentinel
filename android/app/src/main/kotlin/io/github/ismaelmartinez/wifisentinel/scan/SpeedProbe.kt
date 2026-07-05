package io.github.ismaelmartinez.wifisentinel.scan

import android.os.SystemClock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.SocketTimeoutException
import java.net.URL

/**
 * Opt-in download throughput probe. Fetches a fixed-size blob from
 * Cloudflare's speed test endpoint and reports the observed throughput via
 * [SpeedMapping]. Bounded twice over: the fetch is a fixed [DOWNLOAD_BYTES]
 * size and each blocking read is capped at the remaining time budget, so the
 * probe can neither stream unbounded data nor outlive [maxDurationMs]. Off by
 * default in the UI to spare mobile data (docs/android-companion.md §3,
 * `speed.download.speedMbps`).
 */
class SpeedProbe {

    /**
     * @return the measured download result, or null only if nothing was
     *   measured (no connectivity, non-2xx response, zero bytes). A stream
     *   that stalls mid-download still yields the throughput observed up to
     *   the last successful read — the user's data was already spent, so the
     *   partial measurement is reported rather than discarded.
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
            // Elapsed time at the last successful read — the honest duration
            // for a stalled transfer, so dead stall time doesn't deflate the
            // reported Mbps.
            var lastProgress = start
            var bytesTransferred = 0L
            val buffer = ByteArray(64 * 1024)
            try {
                connection.inputStream.use { stream ->
                    while (true) {
                        val remainingMs = maxDurationMs - (SystemClock.elapsedRealtime() - start)
                        if (remainingMs <= 0) break
                        // Cap each blocking read at the remaining budget so no
                        // single read can outlive the overall time cap.
                        connection.readTimeout =
                            remainingMs.coerceAtMost(connectTimeoutMs.toLong()).toInt()
                        val read = stream.read(buffer)
                        if (read == -1) break
                        bytesTransferred += read
                        lastProgress = SystemClock.elapsedRealtime()
                    }
                }
            } catch (_: SocketTimeoutException) {
                // Stalled mid-body: fall through and report what was measured
                // up to the stall instead of discarding it.
            }
            val durationMs = lastProgress - start

            SpeedMapping.downloadResult(bytesTransferred, durationMs, target)
                ?.let { LocalScanResult.Speed(download = it) }
        } catch (_: Exception) {
            null
        } finally {
            connection?.disconnect()
        }
    }

    companion object {
        /**
         * Fixed size of the download, the number the opt-in toggle discloses
         * to the user. The Scan screen derives its "~N MB" label from
         * [DOWNLOAD_MEGABYTES] so the consent copy can't drift from the fetch
         * that actually runs. Large enough to saturate a fast link for a
         * measurable window without burning through a data plan.
         */
        const val DOWNLOAD_MEGABYTES = 25L
        const val DOWNLOAD_BYTES = DOWNLOAD_MEGABYTES * 1024 * 1024

        private const val DEFAULT_TARGET =
            "https://speed.cloudflare.com/__down?bytes=$DOWNLOAD_BYTES"
    }
}
