package online.askahuman.lnurl.lnd;

import online.askahuman.lnurl.LnurlException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.io.IOException;
import java.net.ConnectException;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.util.Base64;
import java.util.HexFormat;
import java.util.stream.Stream;

import static online.askahuman.lnurl.lnd.LndPaymentFixtures.sha256Hex;
import static online.askahuman.lnurl.lnd.LndPaymentFixtures.statusLine;
import static online.askahuman.lnurl.lnd.LndPaymentFixtures.succeededLine;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * How {@link LndClient#payInvoice} and {@link LndClient#trackPayment} classify every outcome:
 * confirmed success, confirmed failure, request never sent, and "cannot tell".
 */
class LndClientPaymentOutcomeTest {

    private static final String PREIMAGE = "11".repeat(32);
    private static final String HASH = sha256Hex(PREIMAGE);

    private static LndClient strictClient(HttpClient http) {
        return new LndClient("localhost", 8080, "deadbeef", http, true);
    }

    @SuppressWarnings("unchecked")
    private static HttpClient respondingWith(int status, String body) throws Exception {
        HttpClient http = mock(HttpClient.class);
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(status);
        when(response.body()).thenReturn(body);
        doReturn(response).when(http).send(any(HttpRequest.class), any());
        return http;
    }

    private static HttpClient throwing(Throwable failure) throws Exception {
        HttpClient http = mock(HttpClient.class);
        doThrow(failure).when(http).send(any(HttpRequest.class), any());
        return http;
    }

    @SuppressWarnings("unchecked")
    private static HttpClient trackingResponse(int status, String body) throws Exception {
        HttpClient http = mock(HttpClient.class);
        HttpResponse<Stream<String>> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(status);
        when(response.body()).thenReturn(body.lines());
        doReturn(response).when(http).send(any(HttpRequest.class), any());
        return http;
    }

    @Nested
    @DisplayName("payInvoice")
    class PayInvoice {

        @Test
        void succeeded_returnsVerifiedResult() throws Exception {
            LndClient.PayInvoiceResponse resp = strictClient(respondingWith(200, succeededLine(HASH, PREIMAGE)))
                    .payInvoice("lnbc1");

            assertEquals(HASH, resp.paymentHash());
            assertEquals(PREIMAGE, resp.paymentPreimage());
            assertEquals("SUCCEEDED", resp.status());
        }

        @Test
        void inFlightUpdateFollowedBySucceeded_succeeds() throws Exception {
            String body = statusLine(HASH, "IN_FLIGHT") + "\n" + succeededLine(HASH, PREIMAGE) + "\n";

            assertEquals("SUCCEEDED", strictClient(respondingWith(200, body)).payInvoice("lnbc1").status());
        }

        @Test
        void succeededFollowedByTrailingErrorLine_stillSucceeds() throws Exception {
            String body = succeededLine(HASH, PREIMAGE) + "\n{\"error\":{\"message\":\"stream closed\"}}\n";

            assertEquals("SUCCEEDED", strictClient(respondingWith(200, body)).payInvoice("lnbc1").status());
        }

        @Test
        void failed_throwsPaymentFailedWithReason() throws Exception {
            String body = "{\"result\":{\"payment_hash\":\"" + HASH + "\",\"status\":\"FAILED\","
                    + "\"failure_reason\":\"FAILURE_REASON_NO_ROUTE\"}}";

            PaymentFailedException ex = assertThrows(PaymentFailedException.class,
                    () -> strictClient(respondingWith(200, body)).payInvoice("lnbc1"));
            assertEquals("FAILURE_REASON_NO_ROUTE", ex.getFailureReason());
        }

        @Test
        void failed_withUnrecognisedReasonText_isSanitised() throws Exception {
            String body = "{\"result\":{\"status\":\"FAILED\",\"failure_reason\":\"boom <script> secret\"}}";

            PaymentFailedException ex = assertThrows(PaymentFailedException.class,
                    () -> strictClient(respondingWith(200, body)).payInvoice("lnbc1"));
            assertEquals("UNKNOWN", ex.getFailureReason());
            assertFalse(ex.getMessage().contains("secret"));
        }

        @Test
        void failed_withoutReason_reportsUnknown() throws Exception {
            PaymentFailedException ex = assertThrows(PaymentFailedException.class,
                    () -> strictClient(respondingWith(200, "{\"result\":{\"status\":\"FAILED\"}}"))
                            .payInvoice("lnbc1"));
            assertEquals("UNKNOWN", ex.getFailureReason());
        }

        @Test
        void inFlightOnly_isOutcomeUnknown() throws Exception {
            assertThrows(PaymentOutcomeUnknownException.class,
                    () -> strictClient(respondingWith(200, statusLine(HASH, "IN_FLIGHT"))).payInvoice("lnbc1"));
        }

        @Test
        void errorEnvelope_isOutcomeUnknown() throws Exception {
            String body = "{\"error\":{\"grpc_code\":2,\"http_code\":500,\"message\":\"gateway oops\"}}";

            PaymentOutcomeUnknownException ex = assertThrows(PaymentOutcomeUnknownException.class,
                    () -> strictClient(respondingWith(200, body)).payInvoice("lnbc1"));
            assertFalse(ex.getMessage().contains("gateway oops"), "must not echo gateway text");
        }

        @Test
        void bodyWithoutStatus_isOutcomeUnknown() throws Exception {
            assertThrows(PaymentOutcomeUnknownException.class,
                    () -> strictClient(respondingWith(200, "{\"result\":{\"payment_hash\":\"" + HASH + "\"}}"))
                            .payInvoice("lnbc1"));
        }

        @Test
        void emptyBody_isOutcomeUnknown() throws Exception {
            assertThrows(PaymentOutcomeUnknownException.class,
                    () -> strictClient(respondingWith(200, "")).payInvoice("lnbc1"));
        }

        @Test
        void nonJsonBody_isOutcomeUnknown() throws Exception {
            assertThrows(PaymentOutcomeUnknownException.class,
                    () -> strictClient(respondingWith(200, "<html>Bad Gateway</html>")).payInvoice("lnbc1"));
        }

        @Test
        void succeededWithPreimageThatDoesNotMatchHash_isOutcomeUnknown() throws Exception {
            assertThrows(PaymentOutcomeUnknownException.class,
                    () -> strictClient(respondingWith(200, succeededLine(HASH, "22".repeat(32))))
                            .payInvoice("lnbc1"));
        }

        @Test
        void succeededWithMissingPreimage_isOutcomeUnknown() throws Exception {
            String body = "{\"result\":{\"payment_hash\":\"" + HASH + "\",\"status\":\"SUCCEEDED\"}}";

            assertThrows(PaymentOutcomeUnknownException.class,
                    () -> strictClient(respondingWith(200, body)).payInvoice("lnbc1"));
        }

        @Test
        void succeededWithNonHexPreimage_isOutcomeUnknown() throws Exception {
            assertThrows(PaymentOutcomeUnknownException.class,
                    () -> strictClient(respondingWith(200, succeededLine(HASH, "zz".repeat(32))))
                            .payInvoice("lnbc1"));
        }

        @Test
        void serverErrorStatus_isOutcomeUnknown() throws Exception {
            assertThrows(PaymentOutcomeUnknownException.class,
                    () -> strictClient(respondingWith(502, "")).payInvoice("lnbc1"));
            assertThrows(PaymentOutcomeUnknownException.class,
                    () -> strictClient(respondingWith(500, succeededLine(HASH, PREIMAGE))).payInvoice("lnbc1"));
        }

        @Test
        void rejectedRequestStatus_isPlainLnurlException_notUnknown() throws Exception {
            for (int status : new int[]{400, 401, 403}) {
                LnurlException ex = assertThrows(LnurlException.class,
                        () -> strictClient(respondingWith(status, "{}")).payInvoice("lnbc1"));
                assertEquals(LnurlException.class, ex.getClass(), "HTTP " + status + " means nothing was sent");
            }
        }

        @Test
        void readTimeout_isOutcomeUnknown() throws Exception {
            assertThrows(PaymentOutcomeUnknownException.class,
                    () -> strictClient(throwing(new HttpTimeoutException("request timed out")))
                            .payInvoice("lnbc1"));
        }

        @Test
        void connectionResetMidRequest_isOutcomeUnknown() throws Exception {
            assertThrows(PaymentOutcomeUnknownException.class,
                    () -> strictClient(throwing(new IOException("Connection reset"))).payInvoice("lnbc1"));
        }

        @Test
        void interrupted_isOutcomeUnknown_andKeepsInterruptFlag() throws Exception {
            try {
                assertThrows(PaymentOutcomeUnknownException.class,
                        () -> strictClient(throwing(new InterruptedException())).payInvoice("lnbc1"));
                assertTrue(Thread.currentThread().isInterrupted());
            } finally {
                Thread.interrupted();
            }
        }

        @Test
        void connectionRefused_isPlainLnurlException_notUnknown() throws Exception {
            LnurlException ex = assertThrows(LnurlException.class,
                    () -> strictClient(throwing(new ConnectException("Connection refused"))).payInvoice("lnbc1"));
            assertEquals(LnurlException.class, ex.getClass());
        }

        @Test
        void connectTimeout_isPlainLnurlException_notUnknown() throws Exception {
            LnurlException ex = assertThrows(LnurlException.class,
                    () -> strictClient(throwing(new HttpConnectTimeoutException("connect timed out")))
                            .payInvoice("lnbc1"));
            assertEquals(LnurlException.class, ex.getClass());
        }

        @Test
        void tlsHandshakeFailure_isPlainLnurlException_notUnknown() throws Exception {
            LnurlException ex = assertThrows(LnurlException.class,
                    () -> strictClient(throwing(new javax.net.ssl.SSLHandshakeException("bad cert")))
                            .payInvoice("lnbc1"));
            assertEquals(LnurlException.class, ex.getClass());
        }

        @Test
        void nonStrictClient_fallsBackToMockOnlyForTransportFailure() throws Exception {
            LndClient client = new LndClient("localhost", 8080, "deadbeef",
                    throwing(new IOException("Connection refused")));

            assertEquals("MOCK", client.payInvoice("lnbc1").status());
        }

        @Test
        void nonStrictClient_doesNotMockAnAmbiguousResponse() throws Exception {
            LndClient client = new LndClient("localhost", 8080, "deadbeef",
                    respondingWith(200, statusLine(HASH, "IN_FLIGHT")));

            assertThrows(PaymentOutcomeUnknownException.class, () -> client.payInvoice("lnbc1"));
        }

        @Test
        void request_carriesDeadlineLongerThanLndAttemptTimeout() throws Exception {
            HttpClient http = respondingWith(200, succeededLine(HASH, PREIMAGE));
            strictClient(http).payInvoice("lnbc1");

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(http).send(captor.capture(), any());
            HttpRequest request = captor.getValue();

            assertTrue(request.uri().getPath().endsWith("/v2/router/send"));
            assertTrue(request.timeout().isPresent(), "an HTTP deadline must be set");
            assertTrue(request.timeout().get().toSeconds() > 60, "must outlast LND's own attempt timeout");
        }
    }

    @Nested
    @DisplayName("trackPayment")
    class TrackPayment {

        @Test
        void succeeded_returnsPreimage() throws Exception {
            PaymentTrackResult result = strictClient(trackingResponse(200, succeededLine(HASH, PREIMAGE)))
                    .trackPayment(HASH);

            assertEquals(PaymentTrackResult.Outcome.SUCCEEDED, result.outcome());
            assertEquals(PREIMAGE, result.paymentPreimage());
            assertEquals(HASH, result.paymentHash());
        }

        @Test
        void failed_returnsSanitisedReason() throws Exception {
            String body = "{\"result\":{\"payment_hash\":\"" + HASH + "\",\"status\":\"FAILED\","
                    + "\"failure_reason\":\"FAILURE_REASON_TIMEOUT\"}}";

            PaymentTrackResult result = strictClient(trackingResponse(200, body)).trackPayment(HASH);

            assertEquals(PaymentTrackResult.Outcome.FAILED, result.outcome());
            assertEquals("FAILURE_REASON_TIMEOUT", result.failureReason());
        }

        @Test
        void inFlightAndInitiated_reportInFlight() throws Exception {
            for (String status : new String[]{"IN_FLIGHT", "INITIATED"}) {
                PaymentTrackResult result = strictClient(trackingResponse(200, statusLine(HASH, status)))
                        .trackPayment(HASH);
                assertEquals(PaymentTrackResult.Outcome.IN_FLIGHT, result.outcome(), status);
            }
        }

        @Test
        void onlyFirstLineIsRead() throws Exception {
            String body = statusLine(HASH, "IN_FLIGHT") + "\n" + succeededLine(HASH, PREIMAGE);

            assertEquals(PaymentTrackResult.Outcome.IN_FLIGHT,
                    strictClient(trackingResponse(200, body)).trackPayment(HASH).outcome());
        }

        @Test
        void unknownToLnd_reportsNotInitiated() throws Exception {
            String body = "{\"code\":5,\"message\":\"payment isn't initiated\",\"details\":[]}";

            assertEquals(PaymentTrackResult.Outcome.NOT_INITIATED,
                    strictClient(trackingResponse(404, body)).trackPayment(HASH).outcome());
        }

        @Test
        void otherNotFound_isOutcomeUnknown() throws Exception {
            assertThrows(PaymentOutcomeUnknownException.class,
                    () -> strictClient(trackingResponse(404, "{\"code\":5,\"message\":\"Not Found\"}"))
                            .trackPayment(HASH));
        }

        @Test
        void responseForDifferentPayment_isOutcomeUnknown() throws Exception {
            String otherHash = sha256Hex("22".repeat(32));

            assertThrows(PaymentOutcomeUnknownException.class,
                    () -> strictClient(trackingResponse(200, succeededLine(otherHash, "22".repeat(32))))
                            .trackPayment(HASH));
        }

        @Test
        void succeededWithBadPreimage_isOutcomeUnknown() throws Exception {
            assertThrows(PaymentOutcomeUnknownException.class,
                    () -> strictClient(trackingResponse(200, succeededLine(HASH, "33".repeat(32))))
                            .trackPayment(HASH));
        }

        @Test
        void unrecognisedStatus_isOutcomeUnknown() throws Exception {
            assertThrows(PaymentOutcomeUnknownException.class,
                    () -> strictClient(trackingResponse(200, statusLine(HASH, "SOMETHING_NEW")))
                            .trackPayment(HASH));
        }

        @Test
        void emptyBody_isOutcomeUnknown() throws Exception {
            assertThrows(PaymentOutcomeUnknownException.class,
                    () -> strictClient(trackingResponse(200, "")).trackPayment(HASH));
        }

        @Test
        void serverError_isOutcomeUnknown() throws Exception {
            assertThrows(PaymentOutcomeUnknownException.class,
                    () -> strictClient(trackingResponse(503, "")).trackPayment(HASH));
        }

        @Test
        void unauthorised_isPlainLnurlException() throws Exception {
            LnurlException ex = assertThrows(LnurlException.class,
                    () -> strictClient(trackingResponse(401, "{\"message\":\"permission denied\"}"))
                            .trackPayment(HASH));
            assertEquals(LnurlException.class, ex.getClass());
        }

        @Test
        void transportFailure_isOutcomeUnknown_evenWhenNonStrict() throws Exception {
            LndClient nonStrict = new LndClient("localhost", 8080, "deadbeef",
                    throwing(new ConnectException("Connection refused")));

            assertThrows(PaymentOutcomeUnknownException.class, () -> nonStrict.trackPayment(HASH));
        }

        @Test
        void interrupted_isOutcomeUnknown_andKeepsInterruptFlag() throws Exception {
            try {
                assertThrows(PaymentOutcomeUnknownException.class,
                        () -> strictClient(throwing(new InterruptedException())).trackPayment(HASH));
                assertTrue(Thread.currentThread().isInterrupted());
            } finally {
                Thread.interrupted();
            }
        }

        @Test
        void invalidHash_isRejectedBeforeAnyRequest() {
            HttpClient http = mock(HttpClient.class);
            LndClient client = strictClient(http);

            assertThrows(IllegalArgumentException.class, () -> client.trackPayment("not-a-hash"));
            assertThrows(IllegalArgumentException.class, () -> client.trackPayment(null));
            verifyNoInteractions(http);
        }

        @Test
        void request_usesBase64UrlHashAndHasDeadline() throws Exception {
            String hash = "fb".repeat(32);
            HttpClient http = trackingResponse(200, statusLine(hash, "IN_FLIGHT"));
            strictClient(http).trackPayment(hash);

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(http).send(captor.capture(), any());
            HttpRequest request = captor.getValue();

            String expected = Base64.getUrlEncoder().encodeToString(HexFormat.of().parseHex(hash));
            assertTrue(expected.contains("-") || expected.contains("_") || expected.endsWith("="),
                    "fixture must exercise the url-safe alphabet");
            assertTrue(request.uri().getPath().endsWith("/v2/router/track/" + expected));
            assertEquals("GET", request.method());
            assertTrue(request.timeout().isPresent());
        }
    }
}
