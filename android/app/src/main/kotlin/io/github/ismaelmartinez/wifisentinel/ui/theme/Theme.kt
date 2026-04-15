package io.github.ismaelmartinez.wifisentinel.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

private val DarkScheme = darkColorScheme(
    primary = Color(0xFF2DD4BF),       // teal-400, matches dashboard accent
    secondary = Color(0xFF818CF8),
    background = Color(0xFF0B0F14),
    surface = Color(0xFF111827),
    onPrimary = Color(0xFF042F2E),
    onBackground = Color(0xFFE5E7EB),
    onSurface = Color(0xFFE5E7EB),
)

private val LightScheme = lightColorScheme(
    primary = Color(0xFF0F766E),
    secondary = Color(0xFF4F46E5),
)

/**
 * Wrap the app in MaterialTheme. Dynamic colour is opt-in on Android 12+;
 * otherwise we fall back to the static teal scheme.
 */
@Composable
fun WifiSentinelTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit,
) {
    val colourScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkScheme
        else -> LightScheme
    }
    MaterialTheme(colorScheme = colourScheme, content = content)
}
