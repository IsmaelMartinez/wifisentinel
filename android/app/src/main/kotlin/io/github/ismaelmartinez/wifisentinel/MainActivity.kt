package io.github.ismaelmartinez.wifisentinel

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
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

private enum class PermissionState { UNKNOWN, GRANTED, DENIED }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ScanApp() {
    val context = LocalContext.current
    val scanner = remember { LocalScanner(context) }
    val scope = rememberCoroutineScope()
    val json = remember { Json { prettyPrint = true; encodeDefaults = true } }

    var scanning by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<LocalScanResult?>(null) }
    var permission by remember { mutableStateOf(PermissionState.UNKNOWN) }
    var showRationale by remember { mutableStateOf(false) }

    val scanPermission = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        Manifest.permission.NEARBY_WIFI_DEVICES
    } else {
        Manifest.permission.ACCESS_FINE_LOCATION
    }

    val runScan: () -> Unit = {
        scope.launch {
            scanning = true
            result = scanner.scan(appVersion = BuildConfig.VERSION_NAME)
            scanning = false
        }
        Unit
    }

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        permission = if (granted) PermissionState.GRANTED else PermissionState.DENIED
        if (granted) runScan()
    }

    if (showRationale) {
        AlertDialog(
            onDismissRequest = { showRationale = false },
            title = { Text(stringResource(R.string.permission_rationale_title)) },
            text = { Text(stringResource(R.string.permission_rationale_body)) },
            confirmButton = {
                TextButton(onClick = {
                    showRationale = false
                    permissionLauncher.launch(scanPermission)
                }) { Text(stringResource(R.string.permission_rationale_ok)) }
            },
            dismissButton = {
                TextButton(onClick = { showRationale = false }) {
                    Text(stringResource(R.string.permission_rationale_cancel))
                }
            },
        )
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
                onClick = {
                    when (permission) {
                        PermissionState.GRANTED -> runScan()
                        // Show rationale on first tap and after an explicit
                        // denial so the user knows why we're asking again.
                        PermissionState.UNKNOWN,
                        PermissionState.DENIED -> showRationale = true
                    }
                },
            ) {
                Text(stringResource(R.string.scan_now))
            }

            if (scanning) {
                CircularProgressIndicator()
            }

            if (permission == PermissionState.DENIED) {
                Text(
                    text = stringResource(R.string.permission_denied),
                    color = MaterialTheme.colorScheme.error,
                )
                // Once the user picks "Don't allow" (especially the
                // "don't ask again" variant) the system permission
                // dialog stops appearing, so re-launching the contract
                // resolves denied immediately. This button sends them
                // to the app's settings page where they can grant the
                // permission manually.
                OutlinedButton(onClick = {
                    val intent = Intent(
                        Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                        Uri.fromParts("package", context.packageName, null),
                    ).apply {
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                    context.startActivity(intent)
                }) {
                    Text(stringResource(R.string.open_settings))
                }
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
