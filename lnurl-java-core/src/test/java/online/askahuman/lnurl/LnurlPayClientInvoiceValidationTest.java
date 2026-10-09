package online.askahuman.lnurl;

import online.askahuman.lnurl.LnurlInvoiceRejectedException.Reason;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.SimpleFormatter;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * LUD-06 step 7: the wallet verifies that the amount in the provider's invoice equals the amount
 * it asked for. The provider is not trusted, so a mismatching invoice must never be returned.
 */
@DisplayName("LnurlPayClient invoice validation")
class LnurlPayClientInvoiceValidationTest {

    private static final String ENDPOINT_JSON =
            "{\"tag\":\"payRequest\",\"callback\":\"https://example.com/pay\","
                    + "\"minSendable\":1000,\"maxSendable\":1000000000,\"metadata\":\"[]\"}";

    private static final String ADDRESS = "alice@example.com";
    private static final long SATS = 100;

    /** The instant the fixed test clock reports. */
    private static final Instant NOW = Instant.ofEpochSecond(1_800_000_000L);
    private static final Clock FIXED_CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    private record Setup(LnurlPayClient client, HttpClient http) {}

    @SuppressWarnings("unchecked")
    private static Setup setup(boolean failOnResolutionError, Clock clock, String callbackBody)
            throws Exception {
        var http = mock(HttpClient.class);
        HttpResponse<String> endpoint = mock(HttpResponse.class);
        HttpResponse<String> invoice = mock(HttpResponse.class);
        when(endpoint.statusCode()).thenReturn(200);
        when(endpoint.body()).thenReturn(ENDPOINT_JSON);
        when(invoice.statusCode()).thenReturn(200);
        when(invoice.body()).thenReturn(callbackBody);
        doReturn(endpoint).doReturn(invoice).when(http).send(any(HttpRequest.class), any());
        return new Setup(new LnurlPayClient(http, failOnResolutionError, clock), http);
    }

    /** Strict client on the real clock. */
    private static LnurlPayClient clientReturning(String callbackBody) throws Exception {
        return setup(true, Clock.systemUTC(), callbackBody).client();
    }

    private static LnurlPayClient fixedClient(boolean failOnResolutionError, String invoice)
            throws Exception {
        return setup(failOnResolutionError, FIXED_CLOCK, TestInvoices.callbackBody(invoice)).client();
    }

    /** Builder for an invoice of exactly {@code sats} created at the fixed test clock's "now". */
    private static TestInvoices.Builder invoiceFor(long sats) {
        return TestInvoices.builder().hrp("lnbc" + (sats * 10) + "n").timestamp(NOW.getEpochSecond());
    }

    private static LnurlInvoiceRejectedException assertRejected(Reason reason, LnurlPayClient client) {
        var e = assertThrows(LnurlInvoiceRejectedException.class,
                () -> client.resolveLightningAddress(ADDRESS, SATS));
        assertEquals(reason, e.getReason());
        return e;
    }

    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("reproduction: provider answers with a larger invoice than requested")
    class Reproduction {

        @Test
        @DisplayName("100 sats requested, 10,000 sats invoiced: must be refused")
        void oversizedInvoice_isRefused() throws Exception {
            // 100 sats = 100,000 msat requested; the provider invoices 10,000,000 msat (10,000 sats).
            var oversized = TestInvoices.builder().hrp("lnbc100u").build();
            var client = clientReturning(TestInvoices.callbackBody(oversized));

            var e = assertThrows(LnurlInvoiceRejectedException.class,
                    () -> client.resolveLightningAddress("alice@example.com", 100));

            assertEquals(Reason.AMOUNT_MISMATCH, e.getReason());
        }

        @Test
        @DisplayName("positive control: an invoice for exactly the requested amount is returned")
        void exactInvoice_isReturned() throws Exception {
            var exact = TestInvoices.mainnetForSats(100);
            var client = clientReturning(TestInvoices.callbackBody(exact));

            assertEquals(exact, client.resolveLightningAddress("alice@example.com", 100));
        }
    }

    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("amount")
    class AmountChecks {

        @Test
        @DisplayName("an amountless invoice is refused")
        void amountless_isRefused() throws Exception {
            var client = fixedClient(true, TestInvoices.builder().hrp("lnbc").timestamp(NOW.getEpochSecond()).build());

            assertRejected(Reason.AMOUNTLESS, client);
        }

        @Test
        @DisplayName("an invoice for less than requested is refused")
        void tooSmall_isRefused() throws Exception {
            var client = fixedClient(true, invoiceFor(SATS - 1).build());

            assertRejected(Reason.AMOUNT_MISMATCH, client);
        }

        @Test
        @DisplayName("an invoice for more than requested is refused")
        void tooLarge_isRefused() throws Exception {
            var client = fixedClient(true, invoiceFor(SATS + 1).build());

            assertRejected(Reason.AMOUNT_MISMATCH, client);
        }

        @Test
        @DisplayName("an invoice one millisatoshi below the requested amount is refused")
        void oneMsatBelow_isRefused() throws Exception {
            // 99,999 msat = 999,990 pico-BTC
            var client = fixedClient(true, TestInvoices.builder().hrp("lnbc999990p")
                    .timestamp(NOW.getEpochSecond()).build());

            assertRejected(Reason.AMOUNT_MISMATCH, client);
        }

        @Test
        @DisplayName("an invoice one millisatoshi above the requested amount is refused")
        void oneMsatAbove_isRefused() throws Exception {
            // 100,001 msat = 1,000,010 pico-BTC
            var client = fixedClient(true, TestInvoices.builder().hrp("lnbc1000010p")
                    .timestamp(NOW.getEpochSecond()).build());

            assertRejected(Reason.AMOUNT_MISMATCH, client);
        }

        @ParameterizedTest(name = "{0}")
        @ValueSource(strings = {"lnbc1000n", "lnbc1u", "lnbc1000000p"})
        @DisplayName("the same amount written in any unit is accepted")
        void sameAmountInOtherUnits_isAccepted(String hrp) throws Exception {
            var invoice = TestInvoices.builder().hrp(hrp).timestamp(NOW.getEpochSecond()).build();

            assertEquals(invoice, fixedClient(true, invoice).resolveLightningAddress(ADDRESS, SATS));
        }

        @Test
        @DisplayName("a different network prefix with the right amount is not rejected (network is policy for the caller)")
        void otherNetworkSameAmount_isAccepted() throws Exception {
            var invoice = TestInvoices.builder().hrp("lntb1000n").timestamp(NOW.getEpochSecond()).build();

            assertEquals(invoice, fixedClient(true, invoice).resolveLightningAddress(ADDRESS, SATS));
        }
    }

    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("malformed invoice")
    class MalformedChecks {

        @ParameterizedTest(name = "pr = \"{0}\"")
        @ValueSource(strings = {
                "not-an-invoice",
                "garbage",
                "lnbc100n1test_invoice",   // the placeholder shape older tests used
                "lnbc_regression_invoice",
                "mock_invoice_alice@example.com_100",
                "",
                " ",
        })
        @DisplayName("garbage and placeholder strings are refused as malformed")
        void garbage_isRefusedAsMalformed(String pr) throws Exception {
            assertRejected(Reason.MALFORMED, fixedClient(true, pr));
        }

        @Test
        @DisplayName("an otherwise correct invoice with a bad checksum is refused as malformed")
        void badChecksum_isRefused() throws Exception {
            var valid = invoiceFor(SATS).build();
            var last = valid.charAt(valid.length() - 1);
            var corrupted = valid.substring(0, valid.length() - 1) + (last == 'q' ? 'p' : 'q');

            assertRejected(Reason.MALFORMED, fixedClient(true, corrupted));
        }

        @Test
        @DisplayName("an invoice with a duplicate expiry tag is refused as malformed")
        void duplicateExpiry_isRefused() throws Exception {
            var invoice = invoiceFor(SATS).expirySeconds(600).expiryTags(2).build();

            assertRejected(Reason.MALFORMED, fixedClient(true, invoice));
        }
    }

    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("expiry")
    class ExpiryChecks {

        private final long nowSeconds = NOW.getEpochSecond();

        @Test
        @DisplayName("an invoice whose expiry instant equals now is refused")
        void expiryEqualsNow_isRefused() throws Exception {
            var invoice = invoiceFor(SATS).timestamp(nowSeconds - 3600).build(); // default 3600 s

            assertRejected(Reason.EXPIRED, fixedClient(true, invoice));
        }

        @Test
        @DisplayName("an invoice that expires one second after now is accepted")
        void expiryOneSecondAhead_isAccepted() throws Exception {
            var invoice = invoiceFor(SATS).timestamp(nowSeconds - 3599).build();

            assertEquals(invoice, fixedClient(true, invoice).resolveLightningAddress(ADDRESS, SATS));
        }

        @Test
        @DisplayName("an invoice that expired one second ago is refused")
        void expiredOneSecondAgo_isRefused() throws Exception {
            var invoice = invoiceFor(SATS).timestamp(nowSeconds - 3601).build();

            assertRejected(Reason.EXPIRED, fixedClient(true, invoice));
        }

        @Test
        @DisplayName("an invoice that expired long ago is refused")
        void longExpired_isRefused() throws Exception {
            var invoice = invoiceFor(SATS).timestamp(nowSeconds - 86_400).build();

            assertRejected(Reason.EXPIRED, fixedClient(true, invoice));
        }

        @Test
        @DisplayName("an explicit x tag is honoured: expiry equal to now is refused")
        void explicitExpiryEqualsNow_isRefused() throws Exception {
            var invoice = invoiceFor(SATS).timestamp(nowSeconds - 100).expirySeconds(100).build();

            assertRejected(Reason.EXPIRED, fixedClient(true, invoice));
        }

        @Test
        @DisplayName("an explicit x tag is honoured: expiry one second ahead is accepted")
        void explicitExpiryOneSecondAhead_isAccepted() throws Exception {
            var invoice = invoiceFor(SATS).timestamp(nowSeconds - 100).expirySeconds(101).build();

            assertEquals(invoice, fixedClient(true, invoice).resolveLightningAddress(ADDRESS, SATS));
        }

        @Test
        @DisplayName("a short x tag expires the invoice even though the 3600 s default would not")
        void shortExpiry_overridesDefault() throws Exception {
            var invoice = invoiceFor(SATS).timestamp(nowSeconds - 61).expirySeconds(60).build();

            assertRejected(Reason.EXPIRED, fixedClient(true, invoice));
        }

        @Test
        @DisplayName("a long x tag keeps an invoice alive past the 3600 s default")
        void longExpiry_overridesDefault() throws Exception {
            var invoice = invoiceFor(SATS).timestamp(nowSeconds - 7200).expirySeconds(86_400).build();

            assertEquals(invoice, fixedClient(true, invoice).resolveLightningAddress(ADDRESS, SATS));
        }

        @Test
        @DisplayName("an invoice created in the future is not refused")
        void futureTimestamp_isAccepted() throws Exception {
            var invoice = invoiceFor(SATS).timestamp(nowSeconds + 120).build();

            assertEquals(invoice, fixedClient(true, invoice).resolveLightningAddress(ADDRESS, SATS));
        }
    }

    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("amount overflow")
    class OverflowChecks {

        @ParameterizedTest(name = "strict={0}, amountSats={1}")
        @CsvSource({
                "true,  9223372036854775807",
                "false, 9223372036854775807",
                "true,  9223372036854776",
                "false, 9223372036854776",
        })
        @DisplayName("an amount that overflows millisatoshis is an IllegalArgumentException before any HTTP call")
        void overflowingAmount_isRejectedWithoutNetwork(boolean strict, long amountSats) throws Exception {
            var s = setup(strict, FIXED_CLOCK, TestInvoices.callbackBody(invoiceFor(SATS).build()));

            var e = assertThrows(IllegalArgumentException.class,
                    () -> s.client().resolveLightningAddress(ADDRESS, amountSats));

            assertTrue(e.getMessage().contains("too large"), e.getMessage());
            verify(s.http(), never()).send(any(HttpRequest.class), any());
        }

        @Test
        @DisplayName("the largest amount that still fits is not an overflow (it is stopped by the provider limit)")
        void largestNonOverflowingAmount_reachesProviderLimitCheck() throws Exception {
            var s = setup(true, FIXED_CLOCK, TestInvoices.callbackBody(invoiceFor(SATS).build()));

            var e = assertThrows(IllegalArgumentException.class,
                    () -> s.client().resolveLightningAddress(ADDRESS, Long.MAX_VALUE / 1000));

            assertTrue(e.getMessage().contains("above maximum"), e.getMessage());
        }
    }

    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("lenient mode (failOnResolutionError=false)")
    class LenientMode {

        @ParameterizedTest(name = "{0}")
        @MethodSource("online.askahuman.lnurl.LnurlPayClientInvoiceValidationTest#rejectedInvoices")
        @DisplayName("a refused invoice still throws and is never replaced by a mock invoice")
        void refusedInvoice_throwsEvenInLenientMode(Reason reason, String invoice) throws Exception {
            var client = fixedClient(false, invoice);

            assertRejected(reason, client);
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("online.askahuman.lnurl.LnurlPayClientInvoiceValidationTest#rejectedInvoices")
        @DisplayName("a refused invoice throws the same reason in strict mode")
        void refusedInvoice_throwsInStrictMode(Reason reason, String invoice) throws Exception {
            assertRejected(reason, fixedClient(true, invoice));
        }

        @Test
        @DisplayName("strict and lenient mode return the same invoice when it is valid")
        void validInvoice_sameInBothModes() throws Exception {
            var invoice = invoiceFor(SATS).build();

            var strict = fixedClient(true, invoice).resolveLightningAddress(ADDRESS, SATS);
            var lenient = fixedClient(false, invoice).resolveLightningAddress(ADDRESS, SATS);

            assertEquals(invoice, strict);
            assertEquals(strict, lenient);
            assertFalse(lenient.startsWith("mock_"));
        }

        @Test
        @DisplayName("an HTTP failure from the invoice endpoint still falls back to a mock invoice")
        @SuppressWarnings("unchecked")
        void httpFailure_stillFallsBackToMock() throws Exception {
            var http = mock(HttpClient.class);
            HttpResponse<String> endpoint = mock(HttpResponse.class);
            HttpResponse<String> invoice = mock(HttpResponse.class);
            when(endpoint.statusCode()).thenReturn(200);
            when(endpoint.body()).thenReturn(ENDPOINT_JSON);
            when(invoice.statusCode()).thenReturn(500);
            doReturn(endpoint).doReturn(invoice).when(http).send(any(HttpRequest.class), any());
            var client = new LnurlPayClient(http, false, FIXED_CLOCK);

            var result = client.resolveLightningAddress(ADDRESS, SATS);

            assertEquals("mock_invoice_" + ADDRESS + "_" + SATS, result);
        }
    }

    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("provider text is not echoed")
    class NoEcho {

        @ParameterizedTest(name = "{0}")
        @MethodSource("online.askahuman.lnurl.LnurlPayClientInvoiceValidationTest#rejectedInvoices")
        @DisplayName("the exception message and cause never contain the provider's pr text")
        void exception_doesNotContainProviderText(Reason reason, String invoice) throws Exception {
            for (var strict : new boolean[] {true, false}) {
                var e = assertRejected(reason, fixedClient(strict, invoice));

                if (!invoice.isBlank()) {
                    assertFalse(e.getMessage().contains(invoice), e.getMessage());
                }
                assertNull(e.getCause());
                assertTrue(e.getMessage().startsWith("LNURL-pay invoice rejected (" + reason + ")"));
            }
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("online.askahuman.lnurl.LnurlPayClientInvoiceValidationTest#rejectedInvoices")
        @DisplayName("nothing logged contains the provider's pr text, and the refusal is logged")
        void log_doesNotContainProviderText(Reason reason, String invoice) throws Exception {
            var records = new ArrayList<String>();
            var warnings = new ArrayList<String>();
            var formatter = new SimpleFormatter();
            Handler handler = new Handler() {
                @Override
                public void publish(LogRecord record) {
                    var text = formatter.formatMessage(record);
                    records.add(text);
                    if (record.getLevel().intValue() >= Level.WARNING.intValue()) {
                        warnings.add(text);
                    }
                }

                @Override
                public void flush() {}

                @Override
                public void close() {}
            };
            handler.setLevel(Level.ALL);
            var logger = java.util.logging.Logger.getLogger(LnurlPayClient.class.getName());
            var previousLevel = logger.getLevel();
            logger.setLevel(Level.ALL);
            logger.addHandler(handler);
            try {
                assertRejected(reason, fixedClient(false, invoice));
            } finally {
                logger.removeHandler(handler);
                logger.setLevel(previousLevel);
            }

            assertFalse(warnings.isEmpty(), "the refusal should be logged as a warning");
            assertTrue(warnings.stream().anyMatch(w -> w.contains(reason.name())), warnings.toString());
            if (!invoice.isBlank()) {
                for (var line : records) {
                    assertFalse(line.contains(invoice), line);
                }
            }
            assertTrue(records.stream().noneMatch(line -> line.contains("mock_invoice_")), records.toString());
        }
    }

    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("invoice text format")
    class TextFormat {

        @Test
        @DisplayName("an upper-case invoice (as printed in a QR code) is accepted and returned unchanged")
        void upperCase_acceptedAndReturnedUnchanged() throws Exception {
            var upper = invoiceFor(SATS).build().toUpperCase();

            assertEquals(upper, fixedClient(true, upper).resolveLightningAddress(ADDRESS, SATS));
        }

        @Test
        @DisplayName("a lightning: prefix or surrounding whitespace is refused, in strict and lenient mode")
        void prefixOrWhitespace_refused() throws Exception {
            var valid = invoiceFor(SATS).build();

            for (var strict : new boolean[] {true, false}) {
                assertRejected(Reason.MALFORMED, fixedClient(strict, "lightning:" + valid));
                assertRejected(Reason.MALFORMED, fixedClient(strict, " " + valid));
                assertRejected(Reason.MALFORMED, fixedClient(strict, valid + " "));
            }
        }

        @Test
        @DisplayName("text planted in a refused invoice never reaches the exception message")
        void plantedText_neverInMessage() throws Exception {
            var planted = TestInvoices.builder().hrp("lnzzcanaryzz100n").timestamp(NOW.getEpochSecond()).build();

            for (var strict : new boolean[] {true, false}) {
                var e = assertRejected(Reason.MALFORMED, fixedClient(strict, planted));

                Bolt11InvoiceTest.assertNoFragmentEchoed(planted, e.getMessage());
                assertFalse(e.getMessage().toLowerCase().contains("canary"), e.getMessage());
            }
        }
    }

    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("missing pr")
    class MissingPr {

        @ParameterizedTest(name = "body = {0}")
        @ValueSource(strings = {"{\"pr\":null}", "{}", "{\"status\":\"OK\"}"})
        @DisplayName("a null or absent pr gives the existing invalid-response LnurlException")
        void nullPr_isInvalidResponse(String body) throws Exception {
            var client = setup(true, FIXED_CLOCK, body).client();

            var e = assertThrows(LnurlException.class, () -> client.resolveLightningAddress(ADDRESS, SATS));

            assertFalse(e instanceof LnurlInvoiceRejectedException);
            assertTrue(e.getMessage().contains("Invalid LNURL-pay invoice response"), e.getMessage());
        }

        @Test
        @DisplayName("a null pr is not an invoice refusal, so lenient mode keeps its mock fallback")
        void nullPr_lenientMode_keepsMockFallback() throws Exception {
            var client = setup(false, FIXED_CLOCK, "{\"pr\":null}").client();

            var result = client.resolveLightningAddress(ADDRESS, SATS);

            assertEquals("mock_invoice_" + ADDRESS + "_" + SATS, result);
        }
    }

    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("exception type")
    class ExceptionType {

        @Test
        @DisplayName("LnurlInvoiceRejectedException is an LnurlException, so existing catch blocks still match")
        void rejection_isAnLnurlException() throws Exception {
            var client = fixedClient(true, invoiceFor(SATS + 1).build());

            var e = assertThrows(LnurlException.class, () -> client.resolveLightningAddress(ADDRESS, SATS));

            assertInstanceOf(LnurlInvoiceRejectedException.class, e);
        }
    }

    /** One invalid invoice per refusal reason, valid in every other respect. */
    static Stream<Arguments> rejectedInvoices() {
        var now = NOW.getEpochSecond();
        return Stream.of(
                Arguments.of(Reason.MALFORMED, "lnbc100n1test_invoice"),
                Arguments.of(Reason.MALFORMED, "not-an-invoice"),
                Arguments.of(Reason.MALFORMED, ""),
                Arguments.of(Reason.AMOUNTLESS,
                        TestInvoices.builder().hrp("lnbc").timestamp(now).build()),
                Arguments.of(Reason.AMOUNT_MISMATCH,
                        TestInvoices.builder().hrp("lnbc100u").timestamp(now).build()),
                Arguments.of(Reason.EXPIRED,
                        TestInvoices.builder().hrp("lnbc1000n").timestamp(now - 3600).build()));
    }
}
