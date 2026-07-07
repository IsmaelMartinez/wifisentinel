package io.github.ismaelmartinez.wifisentinel.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for [ScanPresentation] — the survey/title logic the Compose
 * UI leans on. No Android framework types are touched, so these run under
 * `./gradlew test` without an emulator (same rationale as the other JVM tests).
 */
class ScanPresentationTest {

    private fun wifi(ssid: String? = "Net") = LocalScanResult.Wifi(
        ssid = ssid,
        bssid = "aa:bb:cc:dd:ee:ff",
        security = "WPA2",
        channel = 36,
        band = "5 GHz",
        signal = -50,
        txRate = 866,
    )

    @Test
    fun connectedScanIsNotNearbyOnly() {
        assertFalse(ScanPresentation.isNearbyOnly(wifi()))
    }

    @Test
    fun missingWifiIsNearbyOnly() {
        assertTrue(ScanPresentation.isNearbyOnly(null))
    }

    @Test
    fun titlePrefersConnectedSsid() {
        assertEquals(ScanPresentation.Title.Named("HomeNet"), ScanPresentation.title("HomeNet", 4))
    }

    @Test
    fun titleFallsBackToSurveyWhenNoSsidButNearbyCollected() {
        assertEquals(ScanPresentation.Title.Survey(7), ScanPresentation.title(null, 7))
    }

    @Test
    fun emptyButCollectedSurveyIsStillASurvey() {
        // nearbyCount 0 means "collected, none seen" (distinct from null = not
        // collected), so a survey that saw no other APs stays a Survey — it
        // must not fall through to the unknown-network title.
        assertEquals(ScanPresentation.Title.Survey(0), ScanPresentation.title(null, 0))
    }

    @Test
    fun titleIsUnnamedWhenNoSsidAndNothingCollected() {
        // Only a nameless scan that collected no RF list (null) is unknown.
        assertEquals(ScanPresentation.Title.Unnamed, ScanPresentation.title(null, null))
    }

    @Test
    fun blankSsidIsTreatedAsNoName() {
        // A hidden AP surfaces as an empty/blank name — it must not win over a
        // collected survey list, or the row renders a blank title.
        assertEquals(ScanPresentation.Title.Survey(3), ScanPresentation.title("", 3))
    }
}
