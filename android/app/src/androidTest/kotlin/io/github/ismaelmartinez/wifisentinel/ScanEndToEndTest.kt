package io.github.ismaelmartinez.wifisentinel

import android.Manifest
import android.os.Build
import androidx.annotation.StringRes
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.rule.GrantPermissionRule
import io.github.ismaelmartinez.wifisentinel.store.ScanStore
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * End-to-end scan test: taps "Scan now", accepts the in-app rationale dialog,
 * waits for the pipeline (`LocalScanner` → probes → `LocalAnalyser` →
 * `ScanStore`) to finish, and asserts the result rendered and a row landed in
 * scan history. This is the device-dependent glue no JVM test can reach.
 *
 * The CI emulator has no real WiFi, so the test asserts the pipeline degrades
 * honestly — the scan completes, the analysis stage runs, and the record is
 * saved — rather than asserting anything about the network itself (`wifi` may
 * legitimately be null).
 */
@RunWith(AndroidJUnit4::class)
class ScanEndToEndTest {

    // Grant the scan permission up front so the *system* permission dialog
    // never appears (driving it would need UI Automator). The app's own
    // rationale dialog still shows on the first tap — the test taps through
    // it the same way a user would.
    @get:Rule(order = 0)
    val permissionRule: GrantPermissionRule =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            GrantPermissionRule.grant(Manifest.permission.NEARBY_WIFI_DEVICES)
        } else {
            GrantPermissionRule.grant(Manifest.permission.ACCESS_FINE_LOCATION)
        }

    @get:Rule(order = 1)
    val composeRule = createAndroidComposeRule<MainActivity>()

    private val store: ScanStore
        get() = ScanStore.get(InstrumentationRegistry.getInstrumentation().targetContext)

    private fun str(@StringRes id: Int, vararg formatArgs: Any): String =
        composeRule.activity.getString(id, *formatArgs)

    @Before
    fun clearHistory() {
        runBlocking { store.clear() }
    }

    @Test
    fun scanNowCompletesAndSavesToHistory() {
        composeRule.onNodeWithText(str(R.string.scan_now)).performClick()
        composeRule.onNodeWithText(str(R.string.permission_rationale_ok)).performClick()

        // The scan runs on Dispatchers.IO behind an animating spinner, so
        // synchronising on Compose idleness would hang — poll with waitUntil
        // instead. The probes are individually bounded (fresh-AP-scan 5 s,
        // mDNS windows 3 s, TCP sweep ~300 ms per host at concurrency 32,
        // latency probe 5 s) so a scan typically finishes well under 30 s;
        // the generous ceiling absorbs a slow, cold CI emulator.
        composeRule.waitUntil(timeoutMillis = SCAN_TIMEOUT_MS) {
            composeRule
                .onAllNodesWithText(str(R.string.export_scan))
                .fetchSemanticsNodes()
                .isNotEmpty()
        }

        // The result is set before the history save completes, so give the
        // Room write its own (short) wait.
        composeRule.waitUntil(timeoutMillis = SAVE_TIMEOUT_MS) {
            runBlocking { store.history().first() }.isNotEmpty()
        }

        val summary = runBlocking { store.history().first() }.single()
        // The analysis stage always runs, even on a WiFi-less emulator.
        assertNotNull(summary.overallRisk)

        // The saved scan renders as a row on the History screen. Expected
        // texts derive from the stored summary, not from any assumption about
        // the emulator's (virtual) network.
        composeRule.onNodeWithContentDescription(str(R.string.view_history)).performClick()
        composeRule.onNodeWithText(str(R.string.history_empty)).assertDoesNotExist()
        composeRule
            .onNodeWithText(summary.ssid ?: str(R.string.history_unknown_ssid))
            .assertIsDisplayed()
        composeRule
            .onNodeWithText(str(R.string.history_risk, summary.overallRisk!!))
            .assertIsDisplayed()
    }

    private companion object {
        const val SCAN_TIMEOUT_MS = 120_000L
        const val SAVE_TIMEOUT_MS = 10_000L
    }
}
