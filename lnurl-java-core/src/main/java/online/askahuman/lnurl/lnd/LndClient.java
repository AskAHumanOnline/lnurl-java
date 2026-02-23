package online.askahuman.lnurl.lnd;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * LND REST API client for Lightning Network operations.
 *
 * <p>Provides invoice creation, payment status checking, and invoice payment via the LND REST API.
 * Gracefully degrades to mock mode when LND is unavailable, making it suitable for both
 * production and development use.</p>
 *
 * <p>This is a pure Java implementation with no Spring dependencies.
 * Uses {@link java.net.http.HttpClient} for HTTP calls and Jackson for JSON parsing.</p>
 */
public class LndClient {

    private static final System.Logger log = System.getLogger(LndClient.class.getName());

    /** Maximum routing fee we are willing to pay per payout (satoshis). */
    private static final int MAX_FEE_SATS = 100;

    /** How long to attempt a payment before giving up (seconds). */
    private static final int PAYMENT_TIMEOUT_SECONDS = 60;

    /** Bounded to prevent unbounded heap growth under sustained mock-mode load testing. */
    private static final int MAX_MOCK_PAYMENT_ENTRIES = 10_000;

    private record MockPaymentData(String preimage, long createdTime) {}

    private final String baseUrl;
    private final String macaroon;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Map<String, MockPaymentData> mockPayments = new ConcurrentHashMap<>();
    private final AtomicBoolean mockMode = new AtomicBoolean(false);

    /**
     * Create an LndClient with an already hex-encoded macaroon and a pre-built HttpClient.
     *
     * @param host       LND host
     * @param restPort   LND REST port
     * @param macaroon   hex-encoded admin macaroon
     * @param httpClient the HTTP client to use (should be configured with TLS if needed)
     */
    private LndClient(String host, int restPort, String macaroon, HttpClient httpClient) {
        this.baseUrl = "https://" + host + ":" + restPort;
        this.macaroon = macaroon;
        this.httpClient = httpClient;
        log.log(System.Logger.Level.INFO, "LndClient initialized for {0}:{1}", host, String.valueOf(restPort));
    }

    /**
     * Create an LndClient with an already hex-encoded macaroon string.
     * Uses a default HttpClient (no custom TLS).
     *
     * @param host     LND host
     * @param restPort LND REST port
     * @param macaroon hex-encoded admin macaroon
     */
    public LndClient(String host, int restPort, String macaroon) {
        this(host, restPort, macaroon, HttpClient.newHttpClient());
    }

    /**
     * Factory method that reads the macaroon file, configures TLS from the cert file,
     * and returns an LndClient. Falls back to a dummy macaroon if the file cannot be read.
     *
     * @param host         LND host
     * @param restPort     LND REST port
     * @param macaroonPath path to the LND admin macaroon file
     * @param tlsCertPath  path to the LND TLS certificate file
     * @return a configured LndClient instance
     */
    public static LndClient withMacaroonFile(String host, int restPort, String macaroonPath, String tlsCertPath) {
        // Try to read macaroon file, use dummy value if not available (for testing)
        String macaroonValue;
        try {
            macaroonValue = readMacaroonAsHex(macaroonPath);
            log.log(System.Logger.Level.INFO,
                    "LndClient initialized with macaroon for {0}:{1}", host, String.valueOf(restPort));
        } catch (Exception e) {
            log.log(System.Logger.Level.WARNING,
                    "Could not read LND macaroon file: {0}. Using dummy value for testing.", e.getMessage());
            macaroonValue = "dummy_macaroon_for_testing";
        }

        // Configure TLS cert if available
        SSLContext sslContext = loadTlsCert(tlsCertPath);
        HttpClient.Builder builder = HttpClient.newBuilder();
        if (sslContext != null) {
            builder.sslContext(sslContext);
            log.log(System.Logger.Level.INFO, "LndClient configured with TLS cert from {0}", tlsCertPath);
        }
        HttpClient httpClient = builder.build();

        return new LndClient(host, restPort, macaroonValue, httpClient);
    }

    /**
     * Create a Lightning invoice.
     *
     * @param amountSats    invoice amount in satoshis
     * @param memo          invoice memo/description
     * @param expirySeconds invoice expiry time in seconds
     * @return the created invoice response
     */
    public CreateInvoiceResponse createInvoice(long amountSats, String memo, long expirySeconds) {
        try {
            String json = objectMapper.writeValueAsString(Map.of(
                    "value", String.valueOf(amountSats),
                    "memo", memo,
                    "expiry", String.valueOf(expirySeconds)
            ));

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/v1/invoices"))
                    .header("Grpc-Metadata-macaroon", macaroon)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            CreateInvoiceResponse result = objectMapper.readValue(response.body(), CreateInvoiceResponse.class);

            mockMode.set(false);
            log.log(System.Logger.Level.INFO, "Created invoice: {0} sats, hash: {1}",
                    String.valueOf(amountSats), result.rHash());
            return result;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return createMockInvoice(amountSats, e);
        } catch (Exception e) {
            return createMockInvoice(amountSats, e);
        }
    }

    private CreateInvoiceResponse createMockInvoice(long amountSats, Exception e) {
        mockMode.set(true);
        log.log(System.Logger.Level.WARNING,
                "LND not available, creating mock invoice for testing: {0}", e.getMessage());
        try {
            byte[] preimageBytes = new byte[32];
            new SecureRandom().nextBytes(preimageBytes);
            String preimageHex = bytesToHex(preimageBytes);
            byte[] hashBytes = MessageDigest.getInstance("SHA-256").digest(preimageBytes);
            String paymentHashHex = bytesToHex(hashBytes);
            if (mockPayments.size() < MAX_MOCK_PAYMENT_ENTRIES) {
                mockPayments.put(paymentHashHex, new MockPaymentData(preimageHex, System.currentTimeMillis()));
            } else {
                log.log(System.Logger.Level.WARNING,
                        "mockPayments map at capacity ({0}), not storing new mock payment hash",
                        String.valueOf(MAX_MOCK_PAYMENT_ENTRIES));
            }
            return new CreateInvoiceResponse(
                    paymentHashHex,
                    "lnbc" + amountSats + "u1pwjfml6pp5test_mock_invoice_for_development",
                    null
            );
        } catch (Exception ex) {
            throw new RuntimeException("Failed to generate mock invoice", ex);
        }
    }

    /**
     * Check if an invoice has been paid (settled).
     *
     * @param paymentHash the payment hash to check
     * @return true if the invoice is settled
     */
    public boolean isInvoicePaid(String paymentHash) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/v1/invoice/" + paymentHash))
                    .header("Grpc-Metadata-macaroon", macaroon)
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            Invoice invoice = objectMapper.readValue(response.body(), Invoice.class);

            boolean paid = invoice != null && "SETTLED".equals(invoice.state());
            if (paid) {
                mockMode.set(false);
            }
            return paid;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return checkMockPayment(paymentHash, e);
        } catch (Exception e) {
            return checkMockPayment(paymentHash, e);
        }
    }

    private boolean checkMockPayment(String paymentHash, Exception e) {
        mockMode.set(true);
        log.log(System.Logger.Level.WARNING,
                "LND not available, returning mock payment status for testing: {0}", e.getMessage());
        MockPaymentData data = mockPayments.get(paymentHash);
        if (data != null) {
            return (System.currentTimeMillis() - data.createdTime()) > 5000;
        }
        return false;
    }

    /**
     * Returns true if the last LND API call succeeded (real mode), false if mock mode.
     */
    public boolean isConnected() {
        return !mockMode.get();
    }

    /**
     * Returns the mock preimage for a given payment hash (mock mode only).
     * Returns null if the hash was not created in mock mode or is unknown.
     *
     * @param paymentHash the payment hash to look up
     * @return the mock preimage hex string, or null
     */
    public String getMockPreimage(String paymentHash) {
        MockPaymentData data = mockPayments.get(paymentHash);
        return data != null ? data.preimage() : null;
    }

    /**
     * Get invoice details from LND.
     *
     * @param paymentHash the payment hash
     * @return the invoice details
     */
    public Invoice getInvoice(String paymentHash) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/v1/invoice/" + paymentHash))
                    .header("Grpc-Metadata-macaroon", macaroon)
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            return objectMapper.readValue(response.body(), Invoice.class);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return createMockInvoiceDetails(paymentHash);
        } catch (Exception e) {
            log.log(System.Logger.Level.WARNING,
                    "LND not available, returning mock invoice for testing: {0}", e.getMessage());
            return createMockInvoiceDetails(paymentHash);
        }
    }

    private Invoice createMockInvoiceDetails(String paymentHash) {
        MockPaymentData data = mockPayments.get(paymentHash);
        boolean settled = data != null && (System.currentTimeMillis() - data.createdTime()) > 5000;
        return new Invoice(null, paymentHash, null, null, settled ? "SETTLED" : "OPEN", null);
    }

    /**
     * Pay a Lightning invoice via LND SendPaymentV2 (/v2/router/send).
     *
     * <p>Uses the recommended V2 router API instead of the deprecated
     * /v1/channels/transactions endpoint. Key improvements:</p>
     * <ul>
     *   <li>timeout_seconds: payment attempt expires after 60s (no indefinite hangs)</li>
     *   <li>fee_limit_sat: caps routing fees at MAX_FEE_SATS (100 sats by default)</li>
     *   <li>no_inflight_updates: only stream the final SUCCEEDED/FAILED result</li>
     * </ul>
     *
     * <p>The response is a streaming NDJSON body; we read the entire body, then
     * parse the last JSON line to extract the final payment status.</p>
     *
     * @param paymentRequest the BOLT11 invoice to pay
     * @return the payment response
     */
    public PayInvoiceResponse payInvoice(String paymentRequest) {
        try {
            String json = objectMapper.writeValueAsString(Map.of(
                    "payment_request", paymentRequest,
                    "timeout_seconds", PAYMENT_TIMEOUT_SECONDS,
                    "fee_limit_sat", MAX_FEE_SATS,
                    "no_inflight_updates", true
            ));

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/v2/router/send"))
                    .header("Grpc-Metadata-macaroon", macaroon)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            PayInvoiceResponse result = parsePaymentResult(response.body());

            log.log(System.Logger.Level.INFO, "Paid invoice: hash={0}, status={1}",
                    result.paymentHash(), result.status());
            return result;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return createMockPayResponse();
        } catch (Exception e) {
            log.log(System.Logger.Level.WARNING,
                    "LND not available or payment failed, using mock payment: {0}", e.getMessage());
            return createMockPayResponse();
        }
    }

    private PayInvoiceResponse createMockPayResponse() {
        return new PayInvoiceResponse(
                "mock_payout_hash_" + System.currentTimeMillis(),
                "mock_preimage_" + System.currentTimeMillis(),
                "MOCK"
        );
    }

    /**
     * Parse the final payment status from a /v2/router/send NDJSON body.
     * Each line has the form: {"result": {"payment_hash": "...", "status": "SUCCEEDED", ...}}
     */
    private PayInvoiceResponse parsePaymentResult(String ndjsonBody) throws IOException {
        String lastLine = Arrays.stream(ndjsonBody.split("\n"))
                .map(String::trim)
                .filter(line -> !line.isEmpty())
                .reduce((first, second) -> second)
                .orElseThrow(() -> new RuntimeException("Empty response from /v2/router/send"));

        JsonNode root = objectMapper.readTree(lastLine);
        JsonNode result = root.path("result");

        String status = result.path("status").asText("UNKNOWN");
        if ("FAILED".equals(status)) {
            String reason = result.path("failure_reason").asText("unknown");
            throw new RuntimeException("Payment failed: " + reason);
        }

        return new PayInvoiceResponse(
                result.path("payment_hash").asText(),
                result.path("payment_preimage").asText(),
                status
        );
    }

    private static String readMacaroonAsHex(String path) {
        try {
            byte[] macaroonBytes = Files.readAllBytes(Paths.get(path));
            return bytesToHex(macaroonBytes);
        } catch (IOException e) {
            throw new RuntimeException("Could not read Lightning macaroon from: " + path, e);
        }
    }

    private static SSLContext loadTlsCert(String tlsCertPath) {
        try {
            Path certPath = Paths.get(tlsCertPath);
            if (!Files.exists(certPath)) {
                log.log(System.Logger.Level.WARNING,
                        "LND TLS cert not found at {0}. Skipping TLS configuration.", tlsCertPath);
                return null;
            }
            byte[] certBytes = Files.readAllBytes(certPath);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));

            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setCertificateEntry("lnd", cert);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);
            return sslContext;
        } catch (Exception e) {
            log.log(System.Logger.Level.WARNING,
                    "Could not load LND TLS cert: {0}. Skipping TLS configuration.", e.getMessage());
            return null;
        }
    }

    private static String bytesToHex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    // --- DTOs (immutable records) ---

    /**
     * Response from LND invoice creation (/v1/invoices).
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record CreateInvoiceResponse(
            @JsonProperty("r_hash") String rHash,
            @JsonProperty("payment_request") String paymentRequest,
            @JsonProperty("add_index") String addIndex
    ) {}

    /**
     * LND invoice details (/v1/invoice/{hash}).
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Invoice(
            String memo,
            @JsonProperty("r_hash") String rHash,
            @JsonProperty("payment_request") String paymentRequest,
            String value,
            String state,
            @JsonProperty("settle_date") String settleDate
    ) {}

    /**
     * Response from LND payment (/v2/router/send).
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record PayInvoiceResponse(
            @JsonProperty("payment_hash") String paymentHash,
            @JsonProperty("payment_preimage") String paymentPreimage,
            String status
    ) {}
}
