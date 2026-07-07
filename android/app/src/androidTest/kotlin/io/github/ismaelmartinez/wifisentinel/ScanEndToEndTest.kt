package io.github.ismaelmartinez.wifisentinel

import android.Manifest
import android.os.Build
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.GrantPermissionRule
import io.github.ismaelmartinez.wifisentinel.scan.ScanPresentation
import io.github.ismaelmartinez.wifisentinel.store.ScanStore
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * End-to-end scan test: taps "Scan now", waits for the pipeline
 * (`LocalScanner` → probes → `LocalAnalyser` → `ScanStore`) to finish, and
 * asserts the result rendered and a row landed in scan history. This is the
 * device-dependent glue no JVM test can reach.
 *
 * The CI emulator has no real WiFi, so the test asserts the pipeline degrades
 * honestly — the scan completes, the analysis stage runs, and the record is
 * saved — rather than asserting anything about the network itself (`wifi` may
 * legitimately be null).
 */
@RunWith(AndroidJUnit4::class)
class ScanEndToEndTest {

    // Grant the scan permission up front: the Scan screen seeds its permission
    // state from checkSelfPermission, so neither the system dialog nor the
    // app's own rationale dialog appears and the first tap starts the scan.
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
        get() = ScanStore.get(ApplicationProvider.getApplicationContext())

    @Before
    fun clearHistory() {
        runBlocking { store.clear() }
    }

    @Test
    fun scanNowCompletesAndSavesToHistory() {
        composeRule.onNodeWithText(composeRule.str(R.string.scan_now)).performClick()

        // The scan runs on Dispatchers.IO behind an animating spinner, so
        // synchronising on Compose idleness would hang — poll with waitUntil
        // instead. The probes are individually bounded (fresh-AP-scan 5 s,
        // mDNS windows 3 s, TCP sweep ~300 ms per host at concurrency 32,
        // latency probe 5 s) so a scan typically finishes well under 30 s;
        // the generous ceiling absorbs a slow, cold CI emulator.
        composeRule.waitUntil(timeoutMillis = SCAN_TIMEOUT_MS) {
            composeRule
                .onAllNodesWithText(composeRule.str(R.string.export_scan))
                .fetchSemanticsNodes()
                .isNotEmpty()
        }

        // The result is set before the history save completes, so give the
        // Room write its own (short) wait — suspending on the history flow
        // rather than re-querying in a poll loop.
        val summary = runBlocking {
            withTimeout(SAVE_TIMEOUT_MS) {
                store.history().first { it.isNotEmpty() }
            }
        }.single()
        // The analysis stage always runs, even on a WiFi-less emulator.
        assertNotNull(summary.overallRisk)

        // The saved scan renders as a row on the History screen. Expected
        // texts derive from the stored summary, not from any assumption about
        // the emulator's (virtual) network. HistoryScreen collects the Room
        // flow with `initial = emptyList()` and Compose idle-sync does not
        // wait on Room's executor, so wait for the row rather than asserting
        // immediately after the click.
        composeRule.onNodeWithContentDescription(composeRule.str(R.string.view_history)).performClick()
        // Mirror the screen's title logic (survey-aware): on a WiFi-less
        // emulator the scan may land as a nearby-only survey or an unknown
        // network, so derive the expected row title the same way the UI does.
        val expectedTitle = when (val title = ScanPresentation.title(summary.ssid, summary.nearbyCount)) {
            is ScanPresentation.Title.Named -> title.ssid
            is ScanPresentation.Title.Survey ->
                composeRule.str(R.string.history_survey_title, title.nearbyCount)
            ScanPresentation.Title.Unnamed -> composeRule.str(R.string.history_unknown_ssid)
        }
        composeRule.waitUntil(timeoutMillis = SAVE_TIMEOUT_MS) {
            composeRule.onAllNodesWithText(expectedTitle).fetchSemanticsNodes().isNotEmpty()
        }
        composeRule.onNodeWithText(composeRule.str(R.string.history_empty)).assertDoesNotExist()
        composeRule.onNodeWithText(expectedTitle).assertIsDisplayed()
        composeRule
            .onNodeWithText(composeRule.str(R.string.history_risk, summary.overallRisk!!))
            .assertIsDisplayed()
    }

    private companion object {
        const val SCAN_TIMEOUT_MS = 120_000L
        const val SAVE_TIMEOUT_MS = 10_000L
    }
}
