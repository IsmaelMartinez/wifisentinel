package io.github.ismaelmartinez.wifisentinel.scan

import android.os.SystemClock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL

/**
 * Measures round-trip latency to a well-known host with a single HTTP `HEAD`.
 * This is deliberately not a full speed test — the MVP spares mobile data and
 * only reports a coarse internet-reachability latency figure (see
 * docs/android-companion.md §3, `speed.latency.internetMs`).
 */
class LatencyProbe {

    /**
     * @return round-trip time in milliseconds, or null if the probe failed
     *   (no connectivity, timeout, DNS failure, …).
     */
    suspend fun measure(
        target: String = DEFAULT_TARGET,
        timeoutMs: Int = 5_000,
    ): Long? = withContext(Dispatchers.IO) {
        var connection: HttpURLConnection? = null
        try {
            val start = SystemClock.elapsedRealtime()
            connection = (URL(target).openConnection() as HttpURLConnection).apply {
                requestMethod = "HEAD"
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                instanceFollowRedirects = false
            }
            // Force the request to actually go out and the status line to return.
            connection.responseCode
            SystemClock.elapsedRealtime() - start
        } catch (_: Exception) {
            null
        } finally {
            connection?.disconnect()
        }
    }

    private companion object {
        const val DEFAULT_TARGET = "https://www.cloudflare.com/cdn-cgi/trace"
    }
}
