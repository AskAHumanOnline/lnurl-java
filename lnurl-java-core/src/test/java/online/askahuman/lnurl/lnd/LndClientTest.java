package online.askahuman.lnurl.lnd;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Tests for LndClient.
 *
 * <p>Non-strict mode (via package-private 4-arg constructor) is used for tests that verify
 * mock-mode fallback behaviour when LND is unavailable.
 *
 * <p>The {@link LndClient#withMacaroonFile} factory runs in strict mode when a real macaroon
 * path is provided, and non-strict mode (mock fallback) when the macaroon path is blank.
 *
 * Mock invoice payment behaviour:
 * - Mock invoices use a cryptographically valid random preimage + SHA256(preimage) = paymentHash
 * - The preimage is retrievable via getMockPreimage(paymentHash) for L402 flow testing
 * - Invoices are considered "paid" after 5 seconds from creation (tracked via in-memory map)
 */
class LndClientTest {

    /** Creates a non-strict client whose HttpClient always throws IOException (simulates LND down). */
    @SuppressWarnings("unchecked")
    private static LndClient createMockModeClient() throws Exception {
        HttpClient mockHttp = mock(HttpClient.class);
        doThrow(new IOException("Connection refused")).when(mockHttp).send(any(HttpRequest.class), any());
        return new LndClient("localhost", 8180, "dummy_macaroon", mockHttp);
    }

    @Test
    void testInitialization_withMacaroonFile_throwsWhenMacaroonFileNotFound() {
        assertThrows(IllegalStateException.class, () ->
                LndClient.withMacaroonFile("localhost", 8180, "/nonexistent/admin.macaroon", ""),
                "withMacaroonFile must throw when a non-empty macaroon path cannot be read");
    }

    @Test
    void testInitialization_withMacaroonFile_throwsWhenTlsCertNotFound() {
        // Macaroon path is empty (dev mode OK), but TLS cert path is configured and missing
        assertThrows(IllegalStateException.class, () ->
                LndClient.withMacaroonFile("localhost", 8180, "", "/nonexistent/tls.cert"),
                "withMacaroonFile must throw when a non-empty TLS cert path cannot be loaded");
    }

    @Test
    void testInitialization_withMacaroonFile_succeedsWithEmptyPaths() {
        // Both paths empty → dev mode: dummy macaroon, no TLS pinning, no exception
        assertDoesNotThrow(() -> {
            LndClient client = LndClient.withMacaroonFile("localhost", 8180, "", "");
            assertNotNull(client);
        }, "withMacaroonFile must not throw when both paths are empty (development mode)");
    }

    @Test
    @DisplayName("withMacaroonFile with blank macaroon path uses non-strict mode: falls back to mock on LND unavailable")
    void testWithMacaroonFile_blankMacaroonPath_usesNonStrictMode() {
        // Client created via withMacaroonFile with blank path → non-strict mode.
        // With no real LND on port 8180, createInvoice must return a mock invoice instead of throwing.
        LndClient client = LndClient.withMacaroonFile("localhost", 8180, "", "");
        LndClient.CreateInvoiceResponse response = assertDoesNotThrow(
                () -> client.createInvoice(1000L, "Activation fee", 86400L),
                "withMacaroonFile with blank macaroon path must fall back to mock instead of throwing");
        assertNotNull(response.rHash());
        assertEquals(64, response.rHash().length(), "Mock payment hash must be 64-char hex");
        assertNotNull(response.paymentRequest());
    }

    @Test
    void testCreateInvoice_mockFallback_returnsValidCryptoHash() throws Exception {
        LndClient client = createMockModeClient();

        LndClient.CreateInvoiceResponse response = client.createInvoice(100L, "Test", 3600L);

        assertNotNull(response);
        assertNotNull(response.rHash());
        // Hash must be a 64-char hex string (SHA256 output) so L402 preimage verification works
        assertEquals(64, response.rHash().length(),
            "Mock payment hash must be 64-char hex (SHA256 of random preimage)");
        assertTrue(response.rHash().matches("[0-9a-f]+"),
            "Mock payment hash must be lowercase hex");

        assertNotNull(response.paymentRequest());
        assertTrue(response.paymentRequest().startsWith("lnbc"),
            "Mock payment request should start with 'lnbc'");
    }

    @Test
    void testCreateInvoice_mockFallback_preimageIsRetrievable() throws Exception {
        LndClient client = createMockModeClient();

        LndClient.CreateInvoiceResponse response = client.createInvoice(100L, "Test", 3600L);

        String preimage = client.getMockPreimage(response.rHash());
        assertNotNull(preimage, "Mock preimage must be retrievable after invoice creation");
        assertEquals(64, preimage.length(), "Preimage must be 64-char hex (32 random bytes)");
        assertTrue(preimage.matches("[0-9a-f]+"), "Preimage must be lowercase hex");
    }

    @Test
    void testCreateInvoice_mockFallback_eachInvoiceIsUnique() throws Exception {
        LndClient client = createMockModeClient();

        LndClient.CreateInvoiceResponse r1 = client.createInvoice(100L, "First", 3600L);
        LndClient.CreateInvoiceResponse r2 = client.createInvoice(100L, "Second", 3600L);

        assertNotEquals(r1.rHash(), r2.rHash(),
            "Each mock invoice must have a unique payment hash (no UNIQUE constraint violations under load)");
    }

    @Test
    void testIsInvoicePaid_notPaidImmediately() throws Exception {
        LndClient client = createMockModeClient();

        LndClient.CreateInvoiceResponse response = client.createInvoice(100L, "Test", 3600L);

        assertFalse(client.isInvoicePaid(response.rHash()),
            "Newly created mock invoice should not be considered paid (5-second delay not elapsed)");
    }

    @Test
    void testIsInvoicePaid_unknownHash_returnsFalse() throws Exception {
        LndClient client = createMockModeClient();

        // Hash not in the mock map (not created by this client instance) → false
        assertFalse(client.isInvoicePaid("a".repeat(64)),
            "Unknown hash (not in mock map) should return false");
    }

    @Test
    void testIsInvoicePaid_rejectsInvalidPaymentHash() throws Exception {
        LndClient client = createMockModeClient();

        assertThrows(IllegalArgumentException.class, () -> client.isInvoicePaid("not-a-hash"),
                "isInvoicePaid must throw for non-64-char or non-hex paymentHash");
        assertThrows(IllegalArgumentException.class, () -> client.isInvoicePaid(null),
                "isInvoicePaid must throw for null paymentHash");
        // Path traversal attempt
        assertThrows(IllegalArgumentException.class, () ->
                client.isInvoicePaid("../v1/channels/transactions/" + "a".repeat(26)),
                "isInvoicePaid must throw for path traversal paymentHash");
    }

    @Test
    void testGetMockPreimage_unknownHash_returnsNull() throws Exception {
        LndClient client = createMockModeClient();

        assertNull(client.getMockPreimage("a".repeat(64)),
            "getMockPreimage should return null for hashes not created in mock mode");
    }

    @Test
    void testGetInvoice_mockFallback_newInvoiceIsOpen() throws Exception {
        LndClient client = createMockModeClient();

        LndClient.CreateInvoiceResponse response = client.createInvoice(100L, "Test", 3600L);
        LndClient.Invoice invoice = client.getInvoice(response.rHash());

        assertNotNull(invoice);
        assertEquals(response.rHash(), invoice.rHash());
        assertEquals("OPEN", invoice.state(), "Newly created mock invoice should be OPEN (not yet paid)");
    }

    @Test
    void testGetInvoice_unknownHash_returnsOpen() throws Exception {
        LndClient client = createMockModeClient();

        // Valid 64-char hex hash that was never created → OPEN
        LndClient.Invoice invoice = client.getInvoice("a".repeat(64));
        assertNotNull(invoice);
        assertEquals("OPEN", invoice.state());
    }

    @Test
    void testGetInvoice_rejectsInvalidPaymentHash() throws Exception {
        LndClient client = createMockModeClient();

        assertThrows(IllegalArgumentException.class, () -> client.getInvoice("unknownhash"),
                "getInvoice must throw for a non-64-char paymentHash");
        assertThrows(IllegalArgumentException.class, () -> client.getInvoice(null),
                "getInvoice must throw for null paymentHash");
    }

    @Test
    @DisplayName("payInvoice falls back to mock when LND is unavailable")
    void testPayInvoice_mockFallback() throws Exception {
        LndClient client = createMockModeClient();

        LndClient.PayInvoiceResponse response = client.payInvoice("lnbc100u1test");
        assertNotNull(response);
        assertNotNull(response.paymentHash());
        assertTrue(response.paymentHash().startsWith("mock_payout_hash_"));
        assertNotNull(response.paymentPreimage());
    }

    // -------------------------------------------------------------------------
    // Real LND response handling (HTTP success paths via mocked HttpClient)
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Real LND Response Handling")
    class RealLndResponseHandling {

        @SuppressWarnings("unchecked")
        private LndClient clientWith(String responseBody) throws Exception {
            HttpClient mockHttp = mock(HttpClient.class);
            HttpResponse<String> mockResp = mock(HttpResponse.class);
            when(mockResp.body()).thenReturn(responseBody);
            doReturn(mockResp).when(mockHttp).send(any(HttpRequest.class), any());
            return new LndClient("localhost", 8080, "deadbeef", mockHttp);
        }

        // LND REST returns r_hash as standard base64 (protobuf bytes marshaling).
        // createInvoice converts base64 → hex so callers can use it in /v1/invoice/{hash} lookups.
        // 32 zero bytes: base64 = 43×'A' + '=',  hex = 64×'0'
        private static final String ZERO_RHASH_BASE64 = "A".repeat(43) + "=";
        private static final String ZERO_RHASH_HEX    = "0".repeat(64);

        private static final String HASH_64 = "a".repeat(64);

        @Test
        @DisplayName("createInvoice converts LND base64 r_hash to hex")
        void createInvoice_realResponse_parsesRHashAndPaymentRequest() throws Exception {
            LndClient client = clientWith(
                    "{\"r_hash\":\"" + ZERO_RHASH_BASE64 + "\",\"payment_request\":\"lnbc100n1test\",\"add_index\":\"1\"}"
            );

            LndClient.CreateInvoiceResponse resp = client.createInvoice(100L, "Memo", 3600L);

            assertEquals(ZERO_RHASH_HEX, resp.rHash(), "r_hash must be hex-encoded after base64 decode");
            assertEquals("lnbc100n1test", resp.paymentRequest());
            assertTrue(client.isConnected(), "isConnected() must return true after a real LND call");
        }

        @Test
        @DisplayName("isInvoicePaid returns true when LND reports SETTLED")
        void isInvoicePaid_settledInvoice_returnsTrue() throws Exception {
            LndClient client = clientWith("{\"r_hash\":\"" + HASH_64 + "\",\"state\":\"SETTLED\"}");

            assertTrue(client.isInvoicePaid(HASH_64));
            assertTrue(client.isConnected());
        }

        @Test
        @DisplayName("isInvoicePaid returns false when LND reports OPEN")
        void isInvoicePaid_openInvoice_returnsFalse() throws Exception {
            LndClient client = clientWith("{\"r_hash\":\"" + HASH_64 + "\",\"state\":\"OPEN\"}");

            assertFalse(client.isInvoicePaid(HASH_64));
        }

        @Test
        @DisplayName("getInvoice parses state and memo from real LND response")
        void getInvoice_realResponse_parsesFields() throws Exception {
            LndClient client = clientWith(
                    "{\"memo\":\"test memo\",\"r_hash\":\"" + HASH_64 + "\",\"value\":\"100\",\"state\":\"SETTLED\"}"
            );

            LndClient.Invoice invoice = client.getInvoice(HASH_64);

            assertEquals("SETTLED", invoice.state());
            assertEquals("test memo", invoice.memo());
        }

        @Test
        @DisplayName("payInvoice parses SUCCEEDED status from NDJSON response")
        void payInvoice_succeededResponse_parsesFields() throws Exception {
            String ndjson = "{\"result\":{\"payment_hash\":\"hash123\"," +
                    "\"payment_preimage\":\"pre456\",\"status\":\"SUCCEEDED\"}}";
            LndClient client = clientWith(ndjson);

            LndClient.PayInvoiceResponse resp = client.payInvoice("lnbc100n1test");

            assertEquals("hash123", resp.paymentHash());
            assertEquals("pre456", resp.paymentPreimage());
            assertEquals("SUCCEEDED", resp.status());
        }

        @Test
        @DisplayName("payInvoice with FAILED status falls back to mock (non-strict client)")
        void payInvoice_failedResponse_fallsBackToMock() throws Exception {
            // parsePaymentResult throws RuntimeException for FAILED status,
            // but in non-strict mode (package-private constructor), payInvoice catches it and returns mock.
            String ndjson = "{\"result\":{\"payment_hash\":\"h\",\"status\":\"FAILED\"," +
                    "\"failure_reason\":\"FAILURE_REASON_NO_ROUTE\"}}";
            LndClient client = clientWith(ndjson);

            LndClient.PayInvoiceResponse resp = client.payInvoice("lnbc100n1test");
            assertEquals("MOCK", resp.status(), "FAILED LND response should produce a MOCK fallback response in non-strict mode");
        }

        @Test
        @DisplayName("getInfo parses alias, blockHeight and syncedToChain from real LND response")
        void getInfo_realResponse_parsesFields() throws Exception {
            LndClient client = clientWith(
                    "{\"alias\":\"alice\",\"block_height\":840000,\"synced_to_chain\":true}"
            );

            LndClient.NodeInfo info = client.getInfo();

            assertEquals("alice", info.alias());
            assertEquals(840000, info.blockHeight());
            assertTrue(info.syncedToChain());
            assertTrue(client.isConnected(), "isConnected() must be true after a real LND call");
        }

        @Test
        @DisplayName("isConnected returns false before any real LND call (mock mode)")
        void isConnected_returnsFalse_beforeAnyRealCall() throws Exception {
            LndClient client = createMockModeClient();
            // Triggers mock-mode fallback
            client.createInvoice(1L, "test", 60L);
            assertFalse(client.isConnected(), "isConnected() should be false in mock mode");
        }
    }

    @Test
    @DisplayName("getInfo falls back to mock when LND is unavailable")
    void testGetInfo_mockFallback_returnsMockNode() throws Exception {
        LndClient client = createMockModeClient();

        LndClient.NodeInfo info = client.getInfo();

        assertNotNull(info);
        assertEquals("mock", info.alias(), "Mock node alias must be 'mock'");
        assertEquals(0, info.blockHeight(), "Mock block height must be 0");
        assertFalse(info.syncedToChain(), "Mock node must not report synced_to_chain=true");
        assertFalse(client.isConnected(), "isConnected() must be false after mock fallback");
    }

    @Test
    @DisplayName("LndClient implements AutoCloseable")
    void lndClient_implementsAutoCloseable() {
        assertInstanceOf(AutoCloseable.class,
                new LndClient("localhost", 8080, "dummy_macaroon"));
    }

    @Test
    @DisplayName("LndClient.close() completes without error")
    void lndClient_closeCompletesWithoutError() {
        LndClient client = new LndClient("localhost", 8080, "dummy_macaroon");
        assertDoesNotThrow(client::close);
    }
}
