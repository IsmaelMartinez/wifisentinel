package io.github.ismaelmartinez.wifisentinel

import androidx.annotation.StringRes
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.ismaelmartinez.wifisentinel.scan.SpeedProbe
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Emulator smoke test: launches [MainActivity] (the rule wraps an
 * `ActivityScenario`) and asserts the Scan screen composes. This is the
 * "does the app even start" check the JVM tests cannot give us — it exercises
 * the manifest, the theme resources, Compose setup, and the Room singleton
 * initialisation in `onCreate`.
 *
 * Expected texts are resolved from the same string resources the screen
 * renders, so copy edits (or a translated locale) can't break the test —
 * it verifies the screen composed, not that the English copy is unchanged.
 */
@RunWith(AndroidJUnit4::class)
class MainActivitySmokeTest {

    @get:Rule
    val composeRule = createAndroidComposeRule<MainActivity>()

    private fun str(@StringRes id: Int, vararg formatArgs: Any): String =
        composeRule.activity.getString(id, *formatArgs)

    @Test
    fun scanScreenRenders() {
        composeRule.onNodeWithText(str(R.string.scan_now)).assertIsDisplayed()
        composeRule.onNodeWithText(str(R.string.scan_empty_state)).assertIsDisplayed()
        composeRule
            .onNodeWithText(str(R.string.speed_test_toggle, SpeedProbe.DOWNLOAD_MEGABYTES))
            .assertIsDisplayed()
        composeRule
            .onNodeWithContentDescription(str(R.string.view_history))
            .assertIsDisplayed()
    }
}
