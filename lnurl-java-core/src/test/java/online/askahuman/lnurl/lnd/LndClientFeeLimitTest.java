package online.askahuman.lnurl.lnd;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Flow;

import static online.askahuman.lnurl.lnd.LndPaymentFixtures.sha256Hex;
import static online.askahuman.lnurl.lnd.LndPaymentFixtures.succeededLine;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/** The routing fee limit sent in the payment request body. */
class LndClientFeeLimitTest {

    private static final String PREIMAGE = "11".repeat(32);
    private static final String HASH = sha256Hex(PREIMAGE);

    @SuppressWarnings("unchecked")
    private static HttpClient succeeding() throws Exception {
        HttpClient http = mock(HttpClient.class);
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(200);
        when(response.body()).thenReturn(succeededLine(HASH, PREIMAGE));
        doReturn(response).when(http).send(any(HttpRequest.class), any());
        return http;
    }

    private static LndClient clientOver(HttpClient http) {
        return new LndClient("localhost", 8080, "deadbeef", http, true);
    }

    /** Reads the JSON body of the single request sent through the mocked client. */
    private static JsonNode sentBody(HttpClient http) throws Exception {
        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(http).send(captor.capture(), any());
        HttpRequest.BodyPublisher publisher = captor.getValue().bodyPublisher().orElseThrow();

        StringBuilder text = new StringBuilder();
        publisher.subscribe(new Flow.Subscriber<>() {
            @Override
            public void onSubscribe(Flow.Subscription subscription) {
                subscription.request(Long.MAX_VALUE);
            }

            @Override
            public void onNext(ByteBuffer item) {
                text.append(StandardCharsets.UTF_8.decode(item));
            }

            @Override
            public void onError(Throwable throwable) {
                fail(throwable);
            }

            @Override
            public void onComplete() {
            }
        });
        return new ObjectMapper().readTree(text.toString());
    }

    @Test
    @DisplayName("payInvoice(request, maxFeeSats) sends the supplied fee_limit_sat")
    void customLimit_isSentInBody() throws Exception {
        HttpClient http = succeeding();

        LndClient.PayInvoiceResponse response = clientOver(http).payInvoice("lnbc1", 7L);

        JsonNode body = sentBody(http);
        assertEquals(7L, body.get("fee_limit_sat").asLong());
        assertEquals("lnbc1", body.get("payment_request").asText());
        assertEquals("SUCCEEDED", response.status());
    }

    @Test
    @DisplayName("payInvoice(request) still sends a fee_limit_sat of 100")
    void oneArgument_sendsDefaultLimit() throws Exception {
        HttpClient http = succeeding();

        clientOver(http).payInvoice("lnbc1");

        assertEquals(100L, sentBody(http).get("fee_limit_sat").asLong());
    }

    @Test
    @DisplayName("payInvoice rejects a negative limit without sending anything")
    void negativeLimit_isRejected() throws Exception {
        HttpClient http = succeeding();

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> clientOver(http).payInvoice("lnbc1", -1L));

        assertNotNull(ex.getMessage());
        assertTrue(ex.getMessage().contains("maxFeeSats"));
        verifyNoInteractions(http);
    }
}
