package io.github.ismaelmartinez.wifisentinel

import android.Manifest
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.github.ismaelmartinez.wifisentinel.scan.LocalScanResult
import io.github.ismaelmartinez.wifisentinel.scan.LocalScanner
import io.github.ismaelmartinez.wifisentinel.ui.theme.WifiSentinelTheme
import kotlinx.coroutines.launch
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            WifiSentinelTheme {
                ScanApp()
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ScanApp() {
    val context = LocalContext.current
    val scanner = remember { LocalScanner(context) }
    val scope = rememberCoroutineScope()
    val json = remember { Json { prettyPrint = true; encodeDefaults = true } }

    var scanning by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<LocalScanResult?>(null) }

    val scanPermission = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        Manifest.permission.NEARBY_WIFI_DEVICES
    } else {
        Manifest.permission.ACCESS_FINE_LOCATION
    }

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) {
            scope.launch {
                scanning = true
                // Hard-coded for the spike; switch to BuildConfig.VERSION_NAME
                // once we enable `buildFeatures { buildConfig = true }`.
                result = scanner.scan(appVersion = "0.1.0")
                scanning = false
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(title = { Text(stringResource(R.string.app_name)) })
        },
    ) { inner ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(inner)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Button(
                enabled = !scanning,
                onClick = { permissionLauncher.launch(scanPermission) },
            ) {
                Text(stringResource(R.string.scan_now))
            }

            if (scanning) {
                CircularProgressIndicator()
            }

            when (val current = result) {
                null -> Text(stringResource(R.string.scan_empty_state))
                else -> Text(
                    text = json.encodeToString(current),
                    fontFamily = FontFamily.Monospace,
                )
            }

            Spacer(Modifier.height(24.dp))
        }
    }
}
