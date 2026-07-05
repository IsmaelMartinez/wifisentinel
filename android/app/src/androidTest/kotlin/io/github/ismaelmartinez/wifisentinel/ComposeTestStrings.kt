package io.github.ismaelmartinez.wifisentinel

import androidx.activity.ComponentActivity
import androidx.annotation.StringRes
import androidx.compose.ui.test.junit4.AndroidComposeTestRule
import org.junit.rules.TestRule

/**
 * Resolve a string resource through the rule's activity, so tests assert
 * against the same resources the screen renders — copy edits (or a translated
 * locale) can't desynchronise the expectations. Shared by every instrumented
 * test that drives the Compose UI.
 */
fun <R : TestRule, A : ComponentActivity> AndroidComposeTestRule<R, A>.str(
    @StringRes id: Int,
    vararg formatArgs: Any,
): String = activity.getString(id, *formatArgs)
