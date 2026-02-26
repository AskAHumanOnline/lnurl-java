package online.askahuman.lnurl;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Bech32Utils Tests")
class Bech32UtilsTest {

    /**
     * Known-good vector from the LNURL spec README:
     * URL  → https://service.com/api?q=3fc3645b439ce8e7f2553a69e5267081d96dcd340693afabe04be7b0ccd178df
     * LNURL→ LNURL1DP68GURN8GHJ7UM9WFMXJCM99E3K7MF0V9CXJ0M385EKVCENXC6R2C35XVUKXEFCV5MKVV34X5EKZD3EV56NYD3HXQURZEPEXEJXXEPNXSCRVWFNV9NXZCN9XQ6XYEFHVGCXXCMYXYMNSERXFQ5FNS
     */
    @Test
    @DisplayName("should encode known URL to expected LNURL bech32 string")
    void shouldEncodeKnownVector() {
        var url = "https://service.com/api?q=3fc3645b439ce8e7f2553a69e5267081d96dcd340693afabe04be7b0ccd178df";
        var expected = "LNURL1DP68GURN8GHJ7UM9WFMXJCM99E3K7MF0V9CXJ0M385EKVCENXC6R2C35XVUKXEFCV5MKVV34X5EKZD3EV56NYD3HXQURZEPEXEJXXEPNXSCRVWFNV9NXZCN9XQ6XYEFHVGCXXCMYXYMNSERXFQ5FNS";

        var result = Bech32Utils.encodeLnurl(url);

        assertEquals(expected, result);
    }

    @Test
    @DisplayName("should always start with LNURL1")
    void shouldStartWithLnurl1() {
        var result = Bech32Utils.encodeLnurl("https://example.com/auth?tag=login&k1=abc");
        assertTrue(result.startsWith("LNURL1"), "Expected LNURL1 prefix but got: " + result);
    }

    @Test
    @DisplayName("should return uppercase output")
    void shouldReturnUppercase() {
        var result = Bech32Utils.encodeLnurl("https://example.com/auth?tag=login&k1=abc");
        assertEquals(result.toUpperCase(), result);
    }

    @Test
    @DisplayName("should produce different output for different URLs")
    void shouldProduceDifferentOutputForDifferentUrls() {
        var result1 = Bech32Utils.encodeLnurl("https://example.com/auth?tag=login&k1=aaa");
        var result2 = Bech32Utils.encodeLnurl("https://example.com/auth?tag=login&k1=bbb");
        assertNotEquals(result1, result2);
    }

    @Test
    @DisplayName("should encode LNURL-auth callback URL with tag=login")
    void shouldEncodeLnurlAuthUrl() {
        var url = "https://abc123.ngrok-free.app/api/auth/lnurl/callback?tag=login&k1=ed73b70e3967ee0b3e8afe88d952765e149c89456b7de698cf37cb29398854c7";
        var result = Bech32Utils.encodeLnurl(url);

        assertNotNull(result);
        assertTrue(result.startsWith("LNURL1"));
        // Length sanity: at least HRP(5) + separator(1) + data chars + checksum(6)
        assertTrue(result.length() > 12);
    }

    // -------------------------------------------------------------------------
    // Input validation — null / empty / too-long
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("should throw IllegalArgumentException for null URL")
    void encodeLnurl_withNull_throwsException() {
        assertThrows(IllegalArgumentException.class,
                () -> Bech32Utils.encodeLnurl(null),
                "null URL should throw IllegalArgumentException");
    }

    @Test
    @DisplayName("should throw IllegalArgumentException for empty string")
    void encodeLnurl_withEmptyString_throwsException() {
        assertThrows(IllegalArgumentException.class,
                () -> Bech32Utils.encodeLnurl(""),
                "Empty URL should throw IllegalArgumentException");
    }

    @Test
    @DisplayName("should throw IllegalArgumentException for URL exceeding 2000 characters")
    void encodeLnurl_withUrlExceeding2000Chars_throwsException() {
        // Exactly 2001 chars — one over the limit
        String longUrl = "https://example.com/" + "a".repeat(1981);
        assertEquals(2001, longUrl.length(), "Test setup: URL should be exactly 2001 chars");

        assertThrows(IllegalArgumentException.class,
                () -> Bech32Utils.encodeLnurl(longUrl),
                "URL longer than 2000 chars should throw IllegalArgumentException");
    }

    /**
     * A URL of exactly 2000 characters must succeed (boundary condition).
     */
    @Test
    @DisplayName("should accept URL of exactly 2000 characters")
    void encodeLnurl_withUrlOfExactly2000Chars_succeeds() {
        String boundaryUrl = "https://example.com/" + "a".repeat(1980);
        assertEquals(2000, boundaryUrl.length(), "Test setup: URL should be exactly 2000 chars");

        String result = Bech32Utils.encodeLnurl(boundaryUrl);
        assertNotNull(result);
        assertTrue(result.startsWith("LNURL1"));
    }

    // -------------------------------------------------------------------------
    // Determinism and content
    // -------------------------------------------------------------------------

    /**
     * Encoding is deterministic — the same URL must always produce the same LNURL string.
     */
    @Test
    @DisplayName("should produce identical output for the same URL on repeated calls")
    void encodeLnurl_isDeterministic() {
        String url = "https://askahuman.online/api/auth/lnurl/callback?tag=login&k1=test123";
        String first = Bech32Utils.encodeLnurl(url);
        String second = Bech32Utils.encodeLnurl(url);
        assertEquals(first, second, "encodeLnurl must be deterministic");
    }

    /**
     * The tag=login fragment in the URL must survive the bech32 round-trip encoding.
     * We verify this indirectly by checking that two URLs that differ only by the tag
     * produce different encodings — ensuring the tag is part of the encoded payload.
     */
    @Test
    @DisplayName("tag=login in URL affects encoded payload")
    void encodeLnurl_withTagLoginInUrl_encodesTagLoginInPayload() {
        String urlWithLogin = "https://askahuman.online/api/auth/lnurl/callback?tag=login&k1=test123";
        String urlWithOther = "https://askahuman.online/api/auth/lnurl/callback?tag=other&k1=test123";

        String encodedLogin = Bech32Utils.encodeLnurl(urlWithLogin);
        String encodedOther = Bech32Utils.encodeLnurl(urlWithOther);

        assertTrue(encodedLogin.startsWith("LNURL1"), "Should start with LNURL1");
        assertNotEquals(encodedLogin, encodedOther,
                "Different tag values must produce different encodings");
    }

    // =========================================================================
    // decodeLnurl tests
    // =========================================================================

    /**
     * Round-trip: decodeLnurl(encodeLnurl(url)) must return the original URL.
     */
    @Test
    @DisplayName("decodeLnurl should round-trip back to the original URL")
    void decodeLnurl_roundTrip_returnsOriginalUrl() {
        String url = "https://service.com/api?q=3fc3645b439ce8e7f2553a69e5267081d96dcd340693afabe04be7b0ccd178df";
        String encoded = Bech32Utils.encodeLnurl(url);
        String decoded = Bech32Utils.decodeLnurl(encoded);
        assertEquals(url, decoded);
    }

    /**
     * Round-trip with a URL containing query params and fragment-like path segments.
     */
    @Test
    @DisplayName("decodeLnurl should round-trip LNURL-auth callback URL")
    void decodeLnurl_roundTrip_withAuthCallback() {
        String url = "https://askahuman.online/api/auth/lnurl/callback?tag=login&k1=test123";
        assertEquals(url, Bech32Utils.decodeLnurl(Bech32Utils.encodeLnurl(url)));
    }

    /**
     * decodeLnurl must accept lowercase input (canonical form after lowercasing).
     */
    @Test
    @DisplayName("decodeLnurl should accept lowercase LNURL input")
    void decodeLnurl_acceptsLowercaseInput() {
        String url = "https://example.com/auth?tag=login";
        String encoded = Bech32Utils.encodeLnurl(url);
        String lower = encoded.toLowerCase();
        assertEquals(url, Bech32Utils.decodeLnurl(lower));
    }

    /**
     * Known test vector from LUD-01 spec.
     */
    @Test
    @DisplayName("decodeLnurl should decode known LUD-01 test vector")
    void decodeLnurl_knownVector() {
        var lnurl = "LNURL1DP68GURN8GHJ7UM9WFMXJCM99E3K7MF0V9CXJ0M385EKVCENXC6R2C35XVUKXEFCV5MKVV34X5EKZD3EV56NYD3HXQURZEPEXEJXXEPNXSCRVWFNV9NXZCN9XQ6XYEFHVGCXXCMYXYMNSERXFQ5FNS";
        var expectedUrl = "https://service.com/api?q=3fc3645b439ce8e7f2553a69e5267081d96dcd340693afabe04be7b0ccd178df";
        assertEquals(expectedUrl, Bech32Utils.decodeLnurl(lnurl));
    }

    @Test
    @DisplayName("decodeLnurl should throw IllegalArgumentException for null input")
    void decodeLnurl_withNull_throwsException() {
        assertThrows(IllegalArgumentException.class,
                () -> Bech32Utils.decodeLnurl(null));
    }

    @Test
    @DisplayName("decodeLnurl should throw IllegalArgumentException for empty input")
    void decodeLnurl_withEmpty_throwsException() {
        assertThrows(IllegalArgumentException.class,
                () -> Bech32Utils.decodeLnurl(""));
    }

    @Test
    @DisplayName("decodeLnurl should throw IllegalArgumentException for non-LNURL input")
    void decodeLnurl_withNonLnurlInput_throwsException() {
        assertThrows(IllegalArgumentException.class,
                () -> Bech32Utils.decodeLnurl("bc1qexamplebitcoinaddress"));
    }

    @Test
    @DisplayName("decodeLnurl should throw IllegalArgumentException for tampered checksum")
    void decodeLnurl_withTamperedChecksum_throwsException() {
        String url = "https://example.com/auth?tag=login&k1=abc";
        String encoded = Bech32Utils.encodeLnurl(url);
        // Flip the last character to corrupt the checksum
        char last = encoded.charAt(encoded.length() - 1);
        char flipped = (last == 'A') ? 'B' : 'A';
        String tampered = encoded.substring(0, encoded.length() - 1) + flipped;
        assertThrows(IllegalArgumentException.class,
                () -> Bech32Utils.decodeLnurl(tampered));
    }
}
