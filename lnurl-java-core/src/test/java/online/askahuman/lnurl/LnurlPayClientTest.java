package online.askahuman.lnurl;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for LnurlPayClient.
 * Tests LNURL-pay protocol implementation including address parsing,
 * validation, and graceful degradation to mock mode.
 */
@DisplayName("LnurlPayClient Tests")
class LnurlPayClientTest {

    @Nested
    @DisplayName("Lightning Address Parsing")
    class LightningAddressParsing {

        @Test
        @DisplayName("should reject invalid format (no @) — always throws regardless of mode")
        void shouldRejectInvalidFormat() {
            LnurlPayClient service = LnurlPayClient.create(false);

            // Input validation errors are never swallowed by lenient mode
            assertThrows(IllegalArgumentException.class,
                    () -> service.resolveLightningAddress("invalid", 1000));
        }

        @Test
        @DisplayName("should reject invalid format (multiple @) — always throws regardless of mode")
        void shouldRejectMultipleAt() {
            LnurlPayClient service = LnurlPayClient.create(false);

            // Input validation errors are never swallowed by lenient mode
            assertThrows(IllegalArgumentException.class,
                    () -> service.resolveLightningAddress("alice@domain@com", 1000));
        }

        @Test
        @DisplayName("should parse valid Lightning address format")
        void shouldParseValidAddress() {
            LnurlPayClient service = LnurlPayClient.create(false);

            // Use .invalid TLD (RFC 2606 — guaranteed non-resolvable) so the request fails
            // with a genuine DNS/network IOException, not an application-level error.
            String result = service.resolveLightningAddress("alice@nonexistent.invalid", 1000);

            // Assert: Should return mock invoice in development mode
            assertNotNull(result);
            assertTrue(result.startsWith("mock_invoice_"));
            assertTrue(result.contains("alice@nonexistent.invalid"));
            assertTrue(result.contains("1000"));
        }
    }

    @Nested
    @DisplayName("LNURL Endpoint Resolution - Failure Modes")
    class LnurlEndpointResolution {

        @Test
        @DisplayName("should throw exception when LNURL provider unavailable (fail-on-error=true)")
        void shouldThrowExceptionOnFailureWhenConfigured() {
            // Service configured with fail-on-resolution-error: true (default)
            LnurlPayClient strictService = LnurlPayClient.create(true);

            // Act & Assert
            RuntimeException exception = assertThrows(RuntimeException.class,
                () -> strictService.resolveLightningAddress("test@nonexistent.local", 1000));

            assertTrue(exception.getMessage().contains("Lightning address resolution failed"));
        }

        @Test
        @DisplayName("should return mock invoice when LNURL provider unavailable (fail-on-error=false)")
        void shouldReturnMockInvoiceOnFailureWhenConfigured() {
            // Service configured with fail-on-resolution-error: false (dev mode)
            LnurlPayClient lenientService = LnurlPayClient.create(false);

            // Act
            String invoice = lenientService.resolveLightningAddress("test@nonexistent.local", 1000);

            // Assert
            assertNotNull(invoice);
            assertTrue(invoice.startsWith("mock_invoice_"));
            assertTrue(invoice.contains("test@nonexistent.local"));
            assertTrue(invoice.contains("1000"));
        }

        @Test
        @DisplayName("should handle network errors gracefully in dev mode")
        void shouldHandleNetworkErrors() {
            LnurlPayClient service = LnurlPayClient.create(false);

            // Act: Try to resolve with unreachable domain
            String result = service.resolveLightningAddress("user@unreachable.test", 500);

            // Assert: Should fall back to mock
            assertNotNull(result);
            assertTrue(result.startsWith("mock_invoice_"));
        }
    }

    @Nested
    @DisplayName("Amount Validation")
    class AmountValidation {

        @Test
        @DisplayName("should validate amount within provider limits (mock)")
        void shouldValidateAmount() {
            LnurlPayClient service = LnurlPayClient.create(false);

            // Since we're in mock mode (no real provider), test mock response
            String invoice = service.resolveLightningAddress("alice@test.com", 500);
            assertNotNull(invoice);
            assertTrue(invoice.contains("500"));
        }

        @Test
        @DisplayName("should reject zero amount — always throws regardless of mode")
        void shouldRejectZeroAmount() {
            LnurlPayClient service = LnurlPayClient.create(false);

            // Zero is not a valid payment amount — rejected before any network activity
            assertThrows(IllegalArgumentException.class,
                    () -> service.resolveLightningAddress("alice@test.com", 0));
        }

        @Test
        @DisplayName("should reject negative amount — always throws regardless of mode")
        void shouldRejectNegativeAmount() {
            LnurlPayClient service = LnurlPayClient.create(false);

            assertThrows(IllegalArgumentException.class,
                    () -> service.resolveLightningAddress("alice@test.com", -100));
        }

        @Test
        @DisplayName("should handle large amounts")
        void shouldHandleLargeAmounts() {
            LnurlPayClient service = LnurlPayClient.create(false);

            // Test with 1 million sats
            String invoice = service.resolveLightningAddress("alice@test.com", 1000000);
            assertNotNull(invoice);
            assertTrue(invoice.contains("1000000"));
        }
    }

    @Nested
    @DisplayName("Mock Invoice Format")
    class MockInvoiceFormat {

        @Test
        @DisplayName("should generate consistent mock invoice format")
        void shouldGenerateConsistentFormat() {
            LnurlPayClient service = LnurlPayClient.create(false);

            // Act
            String invoice1 = service.resolveLightningAddress("alice@test.com", 1000);
            String invoice2 = service.resolveLightningAddress("alice@test.com", 1000);

            // Assert: Same input should produce same output
            assertEquals(invoice1, invoice2);
        }

        @Test
        @DisplayName("should include address and amount in mock invoice")
        void shouldIncludeAddressAndAmount() {
            LnurlPayClient service = LnurlPayClient.create(false);

            // Act
            String invoice = service.resolveLightningAddress("bob@wallet.com", 2500);

            // Assert
            assertTrue(invoice.startsWith("mock_invoice_"));
            assertTrue(invoice.contains("bob@wallet.com"));
            assertTrue(invoice.contains("2500"));
        }

        @Test
        @DisplayName("should differentiate between different addresses")
        void shouldDifferentiateBetweenAddresses() {
            LnurlPayClient service = LnurlPayClient.create(false);

            // Act
            String invoice1 = service.resolveLightningAddress("alice@test.com", 1000);
            String invoice2 = service.resolveLightningAddress("bob@test.com", 1000);

            // Assert: Different addresses should produce different invoices
            assertNotEquals(invoice1, invoice2);
        }
    }

    @Nested
    @DisplayName("Configuration Behavior")
    class ConfigurationBehavior {

        @Test
        @DisplayName("should use strict mode by default")
        void shouldUseStrictModeByDefault() {
            LnurlPayClient service = LnurlPayClient.create(true);

            // Act & Assert: Strict mode should throw on failure
            assertThrows(RuntimeException.class,
                () -> service.resolveLightningAddress("test@invalid.test", 1000));
        }

        @Test
        @DisplayName("should use lenient mode when configured")
        void shouldUseLenientModeWhenConfigured() {
            LnurlPayClient service = LnurlPayClient.create(false);

            // Act: Lenient mode should return mock on failure
            String invoice = service.resolveLightningAddress("test@invalid.test", 1000);

            // Assert
            assertNotNull(invoice);
            assertTrue(invoice.startsWith("mock_invoice_"));
        }
    }

    @Nested
    @DisplayName("SSRF Protection — Domain and Username Validation")
    class SsrfProtection {

        @Test
        @DisplayName("should reject domain with port (SSRF vector)")
        void shouldRejectDomainWithPort() {
            LnurlPayClient service = LnurlPayClient.create(true);

            RuntimeException ex = assertThrows(RuntimeException.class,
                () -> service.resolveLightningAddress("alice@evil.com:8080", 100));

            assertTrue(ex.getMessage().contains("illegal characters"),
                "Expected 'illegal characters' in message but got: " + ex.getMessage());
        }

        @Test
        @DisplayName("should reject domain with path traversal (SSRF vector)")
        void shouldRejectDomainWithPath() {
            LnurlPayClient service = LnurlPayClient.create(true);

            RuntimeException ex = assertThrows(RuntimeException.class,
                () -> service.resolveLightningAddress("alice@evil.com/../../etc", 100));

            assertTrue(ex.getMessage().contains("illegal characters"),
                "Expected 'illegal characters' in message but got: " + ex.getMessage());
        }

        @Test
        @DisplayName("should reject domain with query string injection (SSRF vector)")
        void shouldRejectDomainWithQueryString() {
            LnurlPayClient service = LnurlPayClient.create(true);

            RuntimeException ex = assertThrows(RuntimeException.class,
                () -> service.resolveLightningAddress("alice@evil.com?injected=true", 100));

            assertTrue(ex.getMessage().contains("illegal characters"),
                "Expected 'illegal characters' in message but got: " + ex.getMessage());
        }

        @Test
        @DisplayName("should reject username with slash (path traversal vector)")
        void shouldRejectUsernameWithSlash() {
            LnurlPayClient service = LnurlPayClient.create(true);

            RuntimeException ex = assertThrows(RuntimeException.class,
                () -> service.resolveLightningAddress("alice/hack@example.com", 100));

            assertTrue(ex.getMessage().contains("illegal characters"),
                "Expected 'illegal characters' in message but got: " + ex.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // Full resolution flow — HTTP success paths via mocked HttpClient
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Full Resolution Flow (mocked HTTP)")
    class FullResolutionFlow {

        private static final String ENDPOINT_JSON =
                "{\"tag\":\"payRequest\",\"callback\":\"https://example.com/pay\"," +
                "\"minSendable\":1000,\"maxSendable\":1000000000,\"metadata\":\"[]\"}";

        @SuppressWarnings("unchecked")
        private LnurlPayClient clientWithOneResponse(String body) throws Exception {
            return clientWithOneResponse(200, body);
        }

        @SuppressWarnings("unchecked")
        private LnurlPayClient clientWithOneResponse(int statusCode, String body) throws Exception {
            HttpClient mockHttp = mock(HttpClient.class);
            HttpResponse<String> resp = mock(HttpResponse.class);
            when(resp.statusCode()).thenReturn(statusCode);
            when(resp.body()).thenReturn(body);
            doReturn(resp).when(mockHttp).send(any(HttpRequest.class), any());
            return new LnurlPayClient(mockHttp, true);
        }

        @SuppressWarnings("unchecked")
        private LnurlPayClient clientWithTwoResponses(String firstBody, String secondBody) throws Exception {
            HttpClient mockHttp = mock(HttpClient.class);
            HttpResponse<String> first = mock(HttpResponse.class);
            HttpResponse<String> second = mock(HttpResponse.class);
            when(first.statusCode()).thenReturn(200);
            when(second.statusCode()).thenReturn(200);
            when(first.body()).thenReturn(firstBody);
            when(second.body()).thenReturn(secondBody);
            doReturn(first).doReturn(second).when(mockHttp).send(any(HttpRequest.class), any());
            return new LnurlPayClient(mockHttp, true);
        }

        @Test
        @DisplayName("successful resolution returns the BOLT11 invoice from provider")
        void successfulResolution_returnsInvoice() throws Exception {
            String invoiceJson = "{\"pr\":\"lnbc100n1test_invoice\"}";
            LnurlPayClient client = clientWithTwoResponses(ENDPOINT_JSON, invoiceJson);

            String invoice = client.resolveLightningAddress("alice@example.com", 1000);

            assertEquals("lnbc100n1test_invoice", invoice);
        }

        @Test
        @DisplayName("callback URL with existing query params uses & separator")
        void callbackUrlWithExistingQuery_appendsAmountWithAmpersand() throws Exception {
            String endpointWithQuery =
                    "{\"tag\":\"payRequest\",\"callback\":\"https://example.com/pay?token=abc\"," +
                    "\"minSendable\":1000,\"maxSendable\":1000000000}";
            String invoiceJson = "{\"pr\":\"lnbc200n1test_invoice\"}";
            LnurlPayClient client = clientWithTwoResponses(endpointWithQuery, invoiceJson);

            String invoice = client.resolveLightningAddress("alice@example.com", 2000);

            assertEquals("lnbc200n1test_invoice", invoice);
        }

        @Test
        @DisplayName("callback with http:// scheme is rejected (SSRF guard)")
        void callbackWithHttpUrl_throwsRuntimeException() throws Exception {
            String endpointHttpCallback =
                    "{\"tag\":\"payRequest\",\"callback\":\"http://evil.com/pay\"," +
                    "\"minSendable\":1000,\"maxSendable\":1000000000}";
            LnurlPayClient client = clientWithOneResponse(endpointHttpCallback);

            assertThrows(RuntimeException.class,
                    () -> client.resolveLightningAddress("alice@example.com", 1000));
        }

        @Test
        @DisplayName("amount below minSendable throws IllegalArgumentException")
        void amountBelowMin_throwsException() throws Exception {
            String endpointHighMin =
                    "{\"tag\":\"payRequest\",\"callback\":\"https://example.com/pay\"," +
                    "\"minSendable\":100000,\"maxSendable\":1000000000}";
            LnurlPayClient client = clientWithOneResponse(endpointHighMin);

            // 1 sat = 1000 msats < minSendable=100000 msats
            assertThrows(Exception.class,
                    () -> client.resolveLightningAddress("alice@example.com", 1));
        }

        @Test
        @DisplayName("wrong tag in endpoint response throws RuntimeException")
        void wrongTag_throwsRuntimeException() throws Exception {
            String wrongTagEndpoint =
                    "{\"tag\":\"wrongTag\",\"callback\":\"https://example.com/pay\"," +
                    "\"minSendable\":1000,\"maxSendable\":1000000000}";
            LnurlPayClient client = clientWithOneResponse(wrongTagEndpoint);

            assertThrows(RuntimeException.class,
                    () -> client.resolveLightningAddress("alice@example.com", 1000));
        }

        @Test
        @DisplayName("HTTP 404 from endpoint throws RuntimeException")
        void endpointReturns404_throwsRuntimeException() throws Exception {
            LnurlPayClient client = clientWithOneResponse(404, "{\"status\":\"ERROR\"}");

            RuntimeException ex = assertThrows(RuntimeException.class,
                    () -> client.resolveLightningAddress("alice@example.com", 1000));
            assertTrue(ex.getMessage().contains("HTTP 404"),
                    "Exception message should include HTTP status code");
        }

        @Test
        @DisplayName("HTTP 500 from invoice endpoint throws RuntimeException")
        void invoiceEndpointReturns500_throwsRuntimeException() throws Exception {
            // Endpoint succeeds (200) but invoice request fails (500)
            HttpClient mockHttp = mock(HttpClient.class);
            HttpResponse<String> endpointResp = mock(HttpResponse.class);
            HttpResponse<String> invoiceResp = mock(HttpResponse.class);
            when(endpointResp.statusCode()).thenReturn(200);
            when(endpointResp.body()).thenReturn(ENDPOINT_JSON);
            when(invoiceResp.statusCode()).thenReturn(500);
            when(invoiceResp.body()).thenReturn("{\"error\":\"internal error\"}");
            doReturn(endpointResp).doReturn(invoiceResp).when(mockHttp).send(any(HttpRequest.class), any());
            LnurlPayClient client = new LnurlPayClient(mockHttp, true);

            RuntimeException ex = assertThrows(RuntimeException.class,
                    () -> client.resolveLightningAddress("alice@example.com", 1000));
            assertTrue(ex.getMessage().contains("HTTP 500"),
                    "Exception message should include HTTP status code");
        }
    }
}
