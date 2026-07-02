package io.github.ismaelmartinez.wifisentinel.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Pure-JVM tests for [WifiMapping], the WiFi/network field mapping extracted
 * from [LocalScanner]. These exercise the same logic the scanner applies to
 * raw `WifiInfo` / `ScanResult` / `DhcpInfo` values, without needing a device
 * or a fake `WifiManager`/`ConnectivityManager`. See docs/android-companion.md §9.
 */
class WifiMappingTest {

    // ---- SSID normalisation --------------------------------------------------

    @Test
    fun stripsQuotesFromSsid() {
        assertEquals("HomeNet", WifiMapping.normaliseSsid("\"HomeNet\""))
    }

    @Test
    fun dropsUnknownSsidPlaceholder() {
        assertNull(WifiMapping.normaliseSsid("<unknown ssid>"))
    }

    @Test
    fun dropsEmptyAndNullSsid() {
        assertNull(WifiMapping.normaliseSsid(""))
        assertNull(WifiMapping.normaliseSsid("\"\""))
        assertNull(WifiMapping.normaliseSsid(null))
    }

    // ---- BSSID normalisation -------------------------------------------------

    @Test
    fun keepsRealBssid() {
        assertEquals("aa:bb:cc:dd:ee:ff", WifiMapping.normaliseBssid("aa:bb:cc:dd:ee:ff"))
    }

    @Test
    fun dropsRedactedBssid() {
        assertNull(WifiMapping.normaliseBssid("02:00:00:00:00:00"))
        assertNull(WifiMapping.normaliseBssid(""))
        assertNull(WifiMapping.normaliseBssid(null))
    }

    // ---- security from capabilities -----------------------------------------

    @Test
    fun mapsSecurityCapabilities() {
        assertEquals("WPA3", WifiMapping.securityFromCapabilities("[WPA3-SAE+FT/SAE][ESS]"))
        assertEquals("WPA2", WifiMapping.securityFromCapabilities("[WPA2-PSK-CCMP][ESS]"))
        assertEquals("WPA", WifiMapping.securityFromCapabilities("[WPA-PSK-TKIP][ESS]"))
        assertEquals("WEP", WifiMapping.securityFromCapabilities("[WEP][ESS]"))
        assertEquals("Open", WifiMapping.securityFromCapabilities("[ESS]"))
    }

    @Test
    fun prefersStrongestAdvertisedSecurity() {
        // Transitional APs advertise both WPA2 and WPA3; the stronger label wins.
        assertEquals("WPA3", WifiMapping.securityFromCapabilities("[WPA2-PSK][WPA3-SAE][ESS]"))
        // WPA2 must not be shadowed by the bare "WPA" substring check.
        assertEquals("WPA2", WifiMapping.securityFromCapabilities("[WPA2-PSK-CCMP][ESS]"))
    }

    @Test
    fun unknownSecurityForNullOrUnrecognised() {
        assertEquals("unknown", WifiMapping.securityFromCapabilities(null))
        assertEquals("unknown", WifiMapping.securityFromCapabilities("[IBSS]"))
    }

    // ---- frequency → channel -------------------------------------------------

    @Test
    fun mapsTwoPointFourGhzChannels() {
        assertEquals(1, WifiMapping.frequencyToChannel(2412))
        assertEquals(6, WifiMapping.frequencyToChannel(2437))
        assertEquals(13, WifiMapping.frequencyToChannel(2472))
        assertEquals(14, WifiMapping.frequencyToChannel(2484))
    }

    @Test
    fun mapsFiveGhzChannels() {
        assertEquals(36, WifiMapping.frequencyToChannel(5180))
        assertEquals(165, WifiMapping.frequencyToChannel(5825))
    }

    @Test
    fun mapsSixGhzChannels() {
        assertEquals(1, WifiMapping.frequencyToChannel(5955))
        assertEquals(5, WifiMapping.frequencyToChannel(5975))
    }

    @Test
    fun unknownFrequencyIsChannelZero() {
        assertEquals(0, WifiMapping.frequencyToChannel(1234))
    }

    // ---- frequency → band ----------------------------------------------------

    @Test
    fun mapsBands() {
        assertEquals("2.4 GHz", WifiMapping.frequencyToBand(2437))
        assertEquals("5 GHz", WifiMapping.frequencyToBand(5180))
        assertEquals("6 GHz", WifiMapping.frequencyToBand(5955))
        assertEquals("unknown", WifiMapping.frequencyToBand(1234))
    }

    // ---- DhcpInfo int → dotted quad -----------------------------------------

    @Test
    fun formatsLittleEndianIpv4() {
        // DhcpInfo packs IPv4 little-endian: low byte is the first octet.
        val packed = 192 or (168 shl 8) or (1 shl 16) or (2 shl 24)
        assertEquals("192.168.1.2", WifiMapping.formatIpv4(packed))
    }

    @Test
    fun formatsIpv4WithHighOctets() {
        val packed = 10 or (0 shl 8) or (0 shl 16) or (255 shl 24)
        assertEquals("10.0.0.255", WifiMapping.formatIpv4(packed))
    }
}
