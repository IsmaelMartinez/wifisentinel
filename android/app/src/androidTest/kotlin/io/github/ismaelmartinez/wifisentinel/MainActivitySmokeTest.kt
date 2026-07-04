package io.github.ismaelmartinez.wifisentinel

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Emulator smoke test: launches [MainActivity] (the rule wraps an
 * `ActivityScenario`) and asserts the Scan screen composes. This is the
 * "does the app even start" check the JVM tests cannot give us — it exercises
 * the manifest, the theme resources, Compose setup, and the Room singleton
 * initialisation in `onCreate`.
 */
@RunWith(AndroidJUnit4::class)
class MainActivitySmokeTest {

    @get:Rule
    val composeRule = createAndroidComposeRule<MainActivity>()

    @Test
    fun scanScreenRenders() {
        composeRule.onNodeWithText("Scan now").assertIsDisplayed()
        composeRule.onNodeWithText("No scan yet", substring = true).assertIsDisplayed()
        composeRule
            .onNodeWithText("Include speed test", substring = true)
            .assertIsDisplayed()
        composeRule.onNodeWithContentDescription("Scan history").assertIsDisplayed()
    }
}
