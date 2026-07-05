package io.github.ismaelmartinez.wifisentinel

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.History
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import io.github.ismaelmartinez.wifisentinel.scan.LocalScanResult
import io.github.ismaelmartinez.wifisentinel.scan.LocalScanner
import io.github.ismaelmartinez.wifisentinel.scan.SpeedProbe
import io.github.ismaelmartinez.wifisentinel.store.ScanStore
import io.github.ismaelmartinez.wifisentinel.store.ScanSummary
import io.github.ismaelmartinez.wifisentinel.ui.theme.WifiSentinelTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

// Shared JSON config for on-screen rendering and file export. Immutable, so a
// single module-level instance is safe to reuse across composables.
private val exportJson = Json { prettyPrint = true; encodeDefaults = true }

private val timestampFormatter: DateTimeFormatter =
    DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneId.systemDefault())

private fun severityColour(severity: LocalScanResult.Severity, scheme: ColorScheme) =
    when (severity) {
        LocalScanResult.Severity.CRITICAL, LocalScanResult.Severity.HIGH -> scheme.error
        LocalScanResult.Severity.MEDIUM -> scheme.tertiary
        LocalScanResult.Severity.LOW, LocalScanResult.Severity.INFO -> scheme.onSurfaceVariant
    }

/** Colour for a stored risk label; falls back to a neutral tone if unknown. */
private fun riskColour(risk: String?, scheme: ColorScheme): Color {
    val severity = risk?.let { runCatching { LocalScanResult.Severity.valueOf(it) }.getOrNull() }
    return if (severity != null) severityColour(severity, scheme) else scheme.onSurfaceVariant
}

/** Format an ISO-8601 instant as a local `yyyy-MM-dd HH:mm`, or echo it raw. */
private fun formatTimestamp(iso: String): String =
    runCatching { timestampFormatter.format(Instant.parse(iso)) }.getOrDefault(iso)

@Composable
private fun AnalysisSummary(analysis: LocalScanResult.Analysis) {
    val scheme = MaterialTheme.colorScheme
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = stringResource(R.string.overall_risk, analysis.overallRisk.name),
            style = MaterialTheme.typography.titleMedium,
            color = severityColour(analysis.overallRisk, scheme),
        )
        if (analysis.partial) {
            Text(
                text = stringResource(R.string.partial_analysis_note),
                style = MaterialTheme.typography.bodySmall,
                color = scheme.onSurfaceVariant,
            )
        }
        analysis.findings.forEach { finding ->
            Column {
                Text(
                    text = "[${finding.severity.name}] ${finding.title}",
                    style = MaterialTheme.typography.bodyMedium,
                    color = severityColour(finding.severity, scheme),
                )
                Text(
                    text = finding.detail,
                    style = MaterialTheme.typography.bodySmall,
                    color = scheme.onSurfaceVariant,
                )
            }
        }
    }
}

/**
 * Renders a scan result: the analysis summary, a JSON export button, and the
 * raw JSON. Shared by the live scan screen and the stored-scan detail screen,
 * so a past scan can be re-viewed and re-exported.
 */
@Composable
private fun ResultView(result: LocalScanResult, exportEnabled: Boolean = true) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/json"),
    ) { uri ->
        if (uri != null) {
            // The result callback runs on the main thread; writing the document
            // (potentially to slow cloud storage) is blocking I/O, so offload it
            // to avoid stutter / ANR.
            scope.launch(Dispatchers.IO) {
                runCatching {
                    context.contentResolver.openOutputStream(uri)?.use { stream ->
                        stream.write(exportJson.encodeToString(result).toByteArray())
                    }
                }
            }
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        result.analysis?.let { AnalysisSummary(it) }

        result.speed?.let { speed ->
            Text(
                text = stringResource(R.string.speed_download_result, speed.download.speedMbps),
                style = MaterialTheme.typography.bodyMedium,
            )
        }

        OutlinedButton(
            enabled = exportEnabled,
            onClick = { exportLauncher.launch("wifisentinel-scan.json") },
        ) {
            Text(stringResource(R.string.export_scan))
        }

        // Cache the serialization so it doesn't re-run on every recomposition
        // (e.g. while scrolling).
        val jsonString = remember(result) { exportJson.encodeToString(result) }
        Text(
            text = jsonString,
            fontFamily = FontFamily.Monospace,
        )
    }
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val store = ScanStore.get(applicationContext)
        setContent {
            WifiSentinelTheme {
                WifiSentinelApp(store)
            }
        }
    }
}

/**
 * The three screens the single-activity app switches between. Kept as a tiny
 * hand-rolled state machine rather than pulling in navigation-compose — there
 * are only three destinations and no deep links (see docs/android-companion.md §8).
 */
private sealed interface Screen {
    data object Scan : Screen
    data object History : Screen
    data class Detail(val scanId: String) : Screen
}

@Composable
private fun WifiSentinelApp(store: ScanStore) {
    var screen by remember { mutableStateOf<Screen>(Screen.Scan) }

    // Hardware / gesture back mirrors the forward navigation: Detail → History → Scan.
    BackHandler(enabled = screen !is Screen.Scan) {
        screen = when (screen) {
            is Screen.Detail -> Screen.History
            else -> Screen.Scan
        }
    }

    when (val current = screen) {
        Screen.Scan -> ScanScreen(store, onOpenHistory = { screen = Screen.History })
        Screen.History -> HistoryScreen(
            store,
            onBack = { screen = Screen.Scan },
            onOpen = { scanId -> screen = Screen.Detail(scanId) },
        )
        is Screen.Detail -> DetailScreen(store, current.scanId, onBack = { screen = Screen.History })
    }
}

private enum class PermissionState { UNKNOWN, GRANTED, DENIED }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ScanScreen(store: ScanStore, onOpenHistory: () -> Unit) {
    val context = LocalContext.current
    val scanner = remember { LocalScanner(context) }
    val scope = rememberCoroutineScope()

    val scanPermission = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        Manifest.permission.NEARBY_WIFI_DEVICES
    } else {
        Manifest.permission.ACCESS_FINE_LOCATION
    }

    var scanning by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<LocalScanResult?>(null) }
    // Seed from the framework so an already-granted permission (a previous
    // launch, or a test's GrantPermissionRule) doesn't re-show the rationale
    // dialog on the first tap of every session.
    var permission by remember {
        mutableStateOf(
            if (ContextCompat.checkSelfPermission(context, scanPermission) ==
                PackageManager.PERMISSION_GRANTED
            ) {
                PermissionState.GRANTED
            } else {
                PermissionState.UNKNOWN
            },
        )
    }
    var showRationale by remember { mutableStateOf(false) }
    // Off by default to spare mobile data — see docs/android-companion.md §3.
    var includeSpeedTest by remember { mutableStateOf(false) }

    val runScan: () -> Unit = {
        scope.launch {
            scanning = true
            // The finally guarantees the spinner clears and the buttons
            // re-enable even if the scan or the save throws.
            try {
                val scanned = scanner.scan(
                    appVersion = BuildConfig.VERSION_NAME,
                    includeSpeedTest = includeSpeedTest,
                )
                result = scanned
                // Persist every completed scan so it shows up in history.
                store.save(scanned)
            } finally {
                scanning = false
            }
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
            TopAppBar(
                title = { Text(stringResource(R.string.app_name)) },
                actions = {
                    IconButton(onClick = onOpenHistory) {
                        Icon(
                            imageVector = Icons.Filled.History,
                            contentDescription = stringResource(R.string.view_history),
                        )
                    }
                },
            )
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

            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Switch(
                    checked = includeSpeedTest,
                    onCheckedChange = { includeSpeedTest = it },
                    enabled = !scanning,
                )
                Text(
                    text = stringResource(
                        R.string.speed_test_toggle,
                        SpeedProbe.DOWNLOAD_MEGABYTES,
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                )
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
                else -> ResultView(current, exportEnabled = !scanning)
            }

            Spacer(Modifier.height(24.dp))
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun HistoryScreen(
    store: ScanStore,
    onBack: () -> Unit,
    onOpen: (String) -> Unit,
) {
    val summaries by store.history().collectAsState(initial = emptyList())

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.history_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.back),
                        )
                    }
                },
            )
        },
    ) { inner ->
        if (summaries.isEmpty()) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(inner)
                    .padding(16.dp),
            ) {
                Text(stringResource(R.string.history_empty))
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(inner),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                items(items = summaries, key = { it.scanId }) { summary ->
                    HistoryRow(summary, onClick = { onOpen(summary.scanId) })
                }
            }
        }
    }
}

@Composable
private fun HistoryRow(summary: ScanSummary, onClick: () -> Unit) {
    val scheme = MaterialTheme.colorScheme
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = summary.ssid ?: stringResource(R.string.history_unknown_ssid),
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                text = formatTimestamp(summary.timestamp),
                style = MaterialTheme.typography.bodySmall,
                color = scheme.onSurfaceVariant,
            )
            summary.overallRisk?.let { risk ->
                Text(
                    text = stringResource(R.string.history_risk, risk),
                    style = MaterialTheme.typography.bodyMedium,
                    color = riskColour(risk, scheme),
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DetailScreen(store: ScanStore, scanId: String, onBack: () -> Unit) {
    var result by remember(scanId) { mutableStateOf<LocalScanResult?>(null) }
    var loading by remember(scanId) { mutableStateOf(true) }

    LaunchedEffect(scanId) {
        result = store.load(scanId)
        loading = false
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(result?.wifi?.ssid ?: stringResource(R.string.history_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.back),
                        )
                    }
                },
            )
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
            when {
                loading -> CircularProgressIndicator()
                result == null -> Text(stringResource(R.string.scan_not_found))
                else -> ResultView(result!!)
            }
        }
    }
}
