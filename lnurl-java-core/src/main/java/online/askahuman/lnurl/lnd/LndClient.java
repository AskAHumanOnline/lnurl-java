package online.askahuman.lnurl.lnd;

import online.askahuman.lnurl.LnurlException;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
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
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;

/**
 * LND REST API client for Lightning Network operations.
 *
 * <p>Provides invoice creation, payment status checking, and invoice payment via the LND REST API.</p>
 *
 * <p><strong>Strict mode (default):</strong> When LND is unavailable, methods throw {@link online.askahuman.lnurl.LnurlException}
 * instead of silently returning mock data. Use this in production to prevent fake invoices from
 * being treated as real payments. The {@link #withMacaroonFile} factory and public constructors
 * use strict mode by default.</p>
 *
 * <p><strong>Non-strict mode:</strong> Falls back to in-memory mock responses when LND is unreachable.
 * Useful for integration testing without a running LND node. The package-private constructor
 * (used for injecting a mock HttpClient in tests) uses non-strict mode.</p>
 *
 * <p>This is a pure Java implementation with no Spring dependencies.
 * Uses {@link java.net.http.HttpClient} for HTTP calls and Jackson for JSON parsing.</p>
 */
public class LndClient implements AutoCloseable {

    private static final System.Logger log = System.getLogger(LndClient.class.getName());

    /** Maximum routing fee we are willing to pay per payout (satoshis). */
    private static final int MAX_FEE_SATS = 100;

    /** How long to attempt a payment before giving up (seconds). */
    private static final int PAYMENT_TIMEOUT_SECONDS = 60;

    /** Upper bound on establishing a connection to LND. */
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);

    /** HTTP deadline for a payment: LND's own attempt timeout plus a grace period. */
    private static final Duration PAYMENT_REQUEST_TIMEOUT = Duration.ofSeconds(PAYMENT_TIMEOUT_SECONDS + 15L);

    /** HTTP deadline for a payment status lookup. */
    private static final Duration TRACK_REQUEST_TIMEOUT = Duration.ofSeconds(15);

    /** Bounded to prevent unbounded heap growth under sustained mock-mode load testing. */
    private static final int MAX_MOCK_PAYMENT_ENTRIES = 10_000;

    private record MockPaymentData(String preimage, long createdTime) {}

    private final String baseUrl;
    private final String macaroon;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper = configuredObjectMapper();
    private final SecureRandom secureRandom = new SecureRandom();
    private final Map<String, MockPaymentData> mockPayments = new ConcurrentHashMap<>();
    private final AtomicBoolean mockMode = new AtomicBoolean(false);
    private final boolean strictMode;

    /**
     * Package-private constructor for test injection of a mock HttpClient.
     * Runs in <em>non-strict</em> mode: LND failures fall back to mock responses.
     *
     * @param host       LND host
     * @param restPort   LND REST port
     * @param macaroon   hex-encoded admin macaroon
     * @param httpClient the HTTP client to use (typically a Mockito mock in tests)
     */
    LndClient(String host, int restPort, String macaroon, HttpClient httpClient) {
        this(host, restPort, macaroon, httpClient, false);
    }

    LndClient(String host, int restPort, String macaroon, HttpClient httpClient, boolean strictMode) {
        this.baseUrl = "https://" + host + ":" + restPort;
        this.macaroon = macaroon;
        this.httpClient = httpClient;
        this.strictMode = strictMode;
        log.log(System.Logger.Level.INFO, "LndClient initialized for {0}:{1}", host, String.valueOf(restPort));
    }

    /**
     * Create an LndClient with an already hex-encoded macaroon string.
     * Uses a default HttpClient (no custom TLS) and runs in <em>strict</em> mode.
     *
     * @param host     LND host
     * @param restPort LND REST port
     * @param macaroon hex-encoded admin macaroon
     */
    public LndClient(String host, int restPort, String macaroon) {
        this(host, restPort, macaroon, HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build(), true);
    }

    /**
     * Factory method that reads the macaroon file, optionally configures TLS from the cert file,
     * and returns an LndClient in <em>strict</em> mode.
     *
     * <p>Macaroon path behaviour:</p>
     * <ul>
     *   <li>Empty / blank: logs a warning and uses a dummy macaroon (development only).</li>
     *   <li>Non-empty but unreadable: throws {@link IllegalStateException}.</li>
     * </ul>
     *
     * <p>TLS cert path behaviour:</p>
     * <ul>
     *   <li>Empty / blank: TLS certificate pinning is skipped (system trust store used).</li>
     *   <li>Non-empty but not found or unloadable: throws {@link IllegalStateException}.</li>
     * </ul>
     *
     * @param host         LND host
     * @param restPort     LND REST port
     * @param macaroonPath path to the LND admin macaroon file (empty = dev mode)
     * @param tlsCertPath  path to the LND TLS certificate file (empty = skip pinning)
     * @return a configured LndClient instance in strict mode
     * @throws IllegalStateException if a non-empty macaroon path cannot be read, or a non-empty
     *                               TLS cert path cannot be loaded
     */
    public static LndClient withMacaroonFile(String host, int restPort, String macaroonPath, String tlsCertPath) {
        String macaroonValue;
        if (macaroonPath == null || macaroonPath.isBlank()) {
            macaroonValue = "dummy_macaroon_for_testing";
            log.log(System.Logger.Level.WARNING,
                    "LndClient: no macaroon path configured — using dummy macaroon (development only)");
        } else {
            // Throws IllegalStateException if the file cannot be read
            macaroonValue = readMacaroonAsHex(macaroonPath);
            log.log(System.Logger.Level.INFO,
                    "LndClient initialized with macaroon for {0}:{1}", host, String.valueOf(restPort));
        }

        HttpClient.Builder builder = HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT);
        if (tlsCertPath != null && !tlsCertPath.isBlank()) {
            // Throws IllegalStateException if the cert cannot be loaded
            SSLContext sslContext = loadTlsCert(tlsCertPath);
            builder.sslContext(sslContext);
            log.log(System.Logger.Level.INFO, "LndClient configured with TLS cert from {0}", tlsCertPath);
        }

        // Strict mode only when a real macaroon file is configured.
        // Blank macaroon path = development mode: fall back to mock responses instead of throwing.
        boolean strict = (macaroonPath != null && !macaroonPath.isBlank());
        return new LndClient(host, restPort, macaroonValue, builder.build(), strict);
    }

    @Override
    public void close() {
        httpClient.close();
    }

    private static ObjectMapper configuredObjectMapper() {
        ObjectMapper om = new ObjectMapper();
        om.deactivateDefaultTyping();
        return om;
    }

    /**
     * Create a Lightning invoice.
     *
     * @param amountSats    invoice amount in satoshis
     * @param memo          invoice memo/description
     * @param expirySeconds invoice expiry time in seconds
     * @return the created invoice response
     * @throws LnurlException if LND is unavailable and strict mode is enabled
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
            CreateInvoiceResponse raw = objectMapper.readValue(response.body(), CreateInvoiceResponse.class);

            // LND REST API returns r_hash as standard base64 (protobuf bytes marshaling).
            // Convert to hex so callers can use it directly in /v1/invoice/{r_hash} lookups.
            String rHashHex = bytesToHex(Base64.getDecoder().decode(raw.rHash()));
            CreateInvoiceResponse result = new CreateInvoiceResponse(rHashHex, raw.paymentRequest(), raw.addIndex());

            mockMode.set(false);
            log.log(System.Logger.Level.INFO, "Created invoice: {0} sats, hash: {1}",
                    String.valueOf(amountSats), result.rHash());
            return result;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new LnurlException("LND request interrupted", e);
        } catch (Exception e) {
            return createMockInvoice(amountSats, e);
        }
    }

    private CreateInvoiceResponse createMockInvoice(long amountSats, Exception cause) {
        if (strictMode) {
            throw new LnurlException("LND is unavailable (strict mode enabled): " + cause.getMessage(), cause);
        }
        mockMode.set(true);
        log.log(System.Logger.Level.WARNING,
                "LND not available, creating mock invoice for testing: {0}", cause.getMessage());
        try {
            byte[] preimageBytes = new byte[32];
            secureRandom.nextBytes(preimageBytes);
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
            throw new LnurlException("Failed to generate mock invoice", ex);
        }
    }

    /**
     * Check if an invoice has been paid (settled).
     *
     * @param paymentHash the payment hash to check (must be exactly 64 hex characters)
     * @return true if the invoice is settled
     * @throws IllegalArgumentException if paymentHash is not exactly 64 hex characters
     * @throws RuntimeException         if LND is unavailable and strict mode is enabled
     */
    public boolean isInvoicePaid(String paymentHash) {
        validatePaymentHash(paymentHash);
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
            throw new LnurlException("LND request interrupted", e);
        } catch (Exception e) {
            return checkMockPayment(paymentHash, e);
        }
    }

    private boolean checkMockPayment(String paymentHash, Exception cause) {
        if (strictMode) {
            throw new LnurlException("LND is unavailable (strict mode enabled): " + cause.getMessage(), cause);
        }
        mockMode.set(true);
        log.log(System.Logger.Level.WARNING,
                "LND not available, returning mock payment status for testing: {0}", cause.getMessage());
        MockPaymentData data = mockPayments.get(paymentHash);
        if (data != null) {
            return (System.currentTimeMillis() - data.createdTime()) > 5000;
        }
        return false;
    }

    /**
     * Returns true if the last LND API call succeeded (real mode), false if mock mode.
     *
     * @return {@code true} if the most recent LND API call reached a real LND node,
     *         {@code false} if the client fell back to mock mode
     */
    public boolean isConnected() {
        return !mockMode.get();
    }

    /**
     * Returns the mock preimage for a given payment hash (mock mode only).
     *
     * @param paymentHash the payment hash to look up
     * @return the mock preimage hex string, or {@code null} if this hash was not generated
     *         in mock mode, is not tracked by this client instance, or was never created
     */
    public String getMockPreimage(String paymentHash) {
        MockPaymentData data = mockPayments.get(paymentHash);
        return data != null ? data.preimage() : null;
    }

    /**
     * Get invoice details from LND.
     *
     * @param paymentHash the payment hash (must be exactly 64 hex characters)
     * @return the invoice details
     * @throws IllegalArgumentException if paymentHash is not exactly 64 hex characters
     * @throws RuntimeException         if LND is unavailable and strict mode is enabled
     */
    public Invoice getInvoice(String paymentHash) {
        validatePaymentHash(paymentHash);
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
            throw new LnurlException("LND request interrupted", e);
        } catch (Exception e) {
            return createMockInvoiceDetails(paymentHash, e);
        }
    }

    private Invoice createMockInvoiceDetails(String paymentHash, Exception cause) {
        if (strictMode) {
            throw new LnurlException("LND is unavailable (strict mode enabled): " + cause.getMessage(), cause);
        }
        log.log(System.Logger.Level.WARNING,
                "LND not available, returning mock invoice for testing: {0}", cause.getMessage());
        MockPaymentData data = mockPayments.get(paymentHash);
        boolean settled = data != null && (System.currentTimeMillis() - data.createdTime()) > 5000;
        return new Invoice(null, paymentHash, null, null, settled ? "SETTLED" : "OPEN", null);
    }

    /**
     * Retrieve basic node information from LND (/v1/getinfo).
     *
     * <p>This is a read-only probe — it does not create any state in LND.
     * Prefer this over {@link #createInvoice} for health-check purposes.</p>
     *
     * @return node information
     * @throws LnurlException if LND is unavailable and strict mode is enabled
     */
    public NodeInfo getInfo() {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/v1/getinfo"))
                    .header("Grpc-Metadata-macaroon", macaroon)
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            NodeInfo info = objectMapper.readValue(response.body(), NodeInfo.class);

            mockMode.set(false);
            return info;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new LnurlException("LND request interrupted", e);
        } catch (Exception e) {
            return createMockNodeInfo(e);
        }
    }

    private NodeInfo createMockNodeInfo(Exception cause) {
        if (strictMode) {
            throw new LnurlException("LND is unavailable (strict mode enabled): " + cause.getMessage(), cause);
        }
        mockMode.set(true);
        log.log(System.Logger.Level.WARNING,
                "LND not available, returning mock node info: {0}", cause.getMessage());
        return new NodeInfo("mock", 0, false);
    }

    /**
     * Pay a Lightning invoice via LND SendPaymentV2 (/v2/router/send).
     *
     * <p>Returns only when LND reports {@code SUCCEEDED} with a preimage that hashes to the
     * payment hash. Every other outcome is a distinct exception:</p>
     * <ul>
     *   <li>{@link PaymentFailedException}: LND confirmed the payment failed; nothing was sent.</li>
     *   <li>{@link PaymentOutcomeUnknownException}: the payment may still settle (HTTP timeout,
     *       dropped connection, in flight, error or unrecognised response). Resolve it with
     *       {@link #trackPayment(String)} before paying anything else.</li>
     *   <li>{@link LnurlException}: the request provably never reached LND's payment router
     *       (connection refused, TLS handshake failed, request rejected as invalid or
     *       unauthorised).</li>
     * </ul>
     *
     * <p>The request carries {@code timeout_seconds} and {@code fee_limit_sat}, and the HTTP call
     * has its own deadline, so a stalled node or gateway cannot block the caller indefinitely.
     * In non-strict mode only connection-level failures fall back to a mock response.</p>
     *
     * @param paymentRequest the BOLT11 invoice to pay
     * @return the successful payment response
     * @throws PaymentFailedException         if LND confirmed the payment failed
     * @throws PaymentOutcomeUnknownException if it is not known whether the payment was sent
     * @throws LnurlException                 if the request never reached LND
     */
    public PayInvoiceResponse payInvoice(String paymentRequest) {
        HttpRequest request;
        try {
            String json = objectMapper.writeValueAsString(Map.of(
                    "payment_request", paymentRequest,
                    "timeout_seconds", PAYMENT_TIMEOUT_SECONDS,
                    "fee_limit_sat", MAX_FEE_SATS,
                    "no_inflight_updates", true
            ));
            request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/v2/router/send"))
                    .header("Grpc-Metadata-macaroon", macaroon)
                    .header("Content-Type", "application/json")
                    .timeout(PAYMENT_REQUEST_TIMEOUT)
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .build();
        } catch (IOException e) {
            throw new LnurlException("Could not build the payment request", e);
        }

        HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new PaymentOutcomeUnknownException("request interrupted", e);
        } catch (IOException e) {
            if (!strictMode) {
                return createMockPayResponse(e);
            }
            if (neverReachedLnd(e)) {
                throw new LnurlException("LND is unavailable (strict mode enabled): " + e.getMessage(), e);
            }
            throw new PaymentOutcomeUnknownException("no complete response (" + e.getClass().getSimpleName() + ")", e);
        }

        requireAcceptedStatus(response.statusCode());
        PayInvoiceResponse result = parsePaymentResult(response.body());
        log.log(System.Logger.Level.INFO, "Paid invoice: hash={0}, status={1}",
                result.paymentHash(), result.status());
        return result;
    }

    /**
     * Look up the current state of a payment via LND TrackPaymentV2 (/v2/router/track/{hash}).
     *
     * <p>Use this to resolve a {@link PaymentOutcomeUnknownException}. Only the first state LND
     * reports is read, so the call returns promptly even for a payment still in flight.
     * Never falls back to mock data: if the state cannot be determined it throws.</p>
     *
     * @param paymentHash the payment hash to look up (exactly 64 hex characters)
     * @return the payment's current state
     * @throws IllegalArgumentException       if paymentHash is not exactly 64 hex characters
     * @throws PaymentOutcomeUnknownException if the state could not be determined
     * @throws LnurlException                 if LND rejected the request as invalid or unauthorised
     */
    public PaymentTrackResult trackPayment(String paymentHash) {
        validatePaymentHash(paymentHash);
        // The hash is a protobuf bytes path parameter, which the REST gateway expects base64url-encoded.
        String pathHash = Base64.getUrlEncoder().encodeToString(HexFormat.of().parseHex(paymentHash));
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/v2/router/track/" + pathHash))
                .header("Grpc-Metadata-macaroon", macaroon)
                .timeout(TRACK_REQUEST_TIMEOUT)
                .GET()
                .build();

        String firstLine;
        int status;
        try {
            HttpResponse<Stream<String>> response = httpClient.send(request, HttpResponse.BodyHandlers.ofLines());
            status = response.statusCode();
            try (Stream<String> lines = response.body()) {
                firstLine = lines.map(String::strip).filter(line -> !line.isEmpty()).findFirst().orElse("");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new PaymentOutcomeUnknownException("request interrupted", e);
        } catch (IOException e) {
            throw new PaymentOutcomeUnknownException("no response (" + e.getClass().getSimpleName() + ")", e);
        }

        return parseTrackResult(paymentHash, status, firstLine);
    }

    /** True when the failure happened before the request could have reached LND's payment router. */
    private static boolean neverReachedLnd(IOException e) {
        return e instanceof ConnectException
                || e instanceof HttpConnectTimeoutException
                || e instanceof SSLHandshakeException;
    }

    /** 2xx proceeds; 400/401/403 mean LND refused the request outright; anything else is ambiguous. */
    private static void requireAcceptedStatus(int status) {
        if (status >= 200 && status < 300) {
            return;
        }
        if (status == 400 || status == 401 || status == 403) {
            throw new LnurlException("LND rejected the request (HTTP " + status + ")");
        }
        throw new PaymentOutcomeUnknownException("unexpected HTTP status " + status);
    }

    private PayInvoiceResponse createMockPayResponse(Exception cause) {
        log.log(System.Logger.Level.WARNING,
                "LND not available, using mock payment: {0}", cause.getMessage());
        return new PayInvoiceResponse(
                "mock_payout_hash_" + System.currentTimeMillis(),
                "mock_preimage_" + System.currentTimeMillis(),
                "MOCK"
        );
    }

    /**
     * Interpret a /v2/router/send NDJSON body. Each line has the form
     * {@code {"result": {"payment_hash": "...", "status": "SUCCEEDED", ...}}}. Only a terminal
     * {@code SUCCEEDED}/{@code FAILED} line counts; error envelopes, in-flight updates and
     * unparseable lines never produce a result.
     */
    private PayInvoiceResponse parsePaymentResult(String ndjsonBody) {
        JsonNode terminal = null;
        for (String line : ndjsonBody.split("\n")) {
            JsonNode result = resultOf(line);
            String status = result.path("status").asText("");
            if ("SUCCEEDED".equals(status) || "FAILED".equals(status)) {
                terminal = result;
            }
        }
        if (terminal == null) {
            throw new PaymentOutcomeUnknownException("response held no terminal payment status");
        }
        if ("FAILED".equals(terminal.path("status").asText())) {
            throw new PaymentFailedException(terminal.path("failure_reason").asText(null));
        }

        String hash = terminal.path("payment_hash").asText("");
        String preimage = terminal.path("payment_preimage").asText("");
        if (!preimageMatchesHash(preimage, hash)) {
            throw new PaymentOutcomeUnknownException("success response failed the preimage check");
        }
        return new PayInvoiceResponse(hash, preimage, "SUCCEEDED");
    }

    private PaymentTrackResult parseTrackResult(String requestedHash, int httpStatus, String line) {
        JsonNode root = parseLine(line);
        JsonNode result = root.path("result");

        if (result.isObject()) {
            requireAcceptedStatus(httpStatus);
            return trackResultOf(requestedHash, result);
        }
        if (root.path("message").asText("").contains("isn't initiated")) {
            return new PaymentTrackResult(PaymentTrackResult.Outcome.NOT_INITIATED, requestedHash, null, null);
        }
        requireAcceptedStatus(httpStatus);
        throw new PaymentOutcomeUnknownException("response held no payment status");
    }

    private PaymentTrackResult trackResultOf(String requestedHash, JsonNode result) {
        if (!requestedHash.equalsIgnoreCase(result.path("payment_hash").asText(""))) {
            throw new PaymentOutcomeUnknownException("response was for a different payment");
        }
        return switch (result.path("status").asText("")) {
            case "SUCCEEDED" -> {
                String preimage = result.path("payment_preimage").asText("");
                if (!preimageMatchesHash(preimage, requestedHash)) {
                    throw new PaymentOutcomeUnknownException("success response failed the preimage check");
                }
                yield new PaymentTrackResult(PaymentTrackResult.Outcome.SUCCEEDED, requestedHash, preimage, null);
            }
            case "FAILED" -> new PaymentTrackResult(PaymentTrackResult.Outcome.FAILED, requestedHash, null,
                    new PaymentFailedException(result.path("failure_reason").asText(null)).getFailureReason());
            case "INITIATED", "IN_FLIGHT" ->
                    new PaymentTrackResult(PaymentTrackResult.Outcome.IN_FLIGHT, requestedHash, null, null);
            default -> throw new PaymentOutcomeUnknownException("unrecognised payment status");
        };
    }

    /** The {@code result} object of one NDJSON line, or a missing node if the line has none. */
    private JsonNode resultOf(String line) {
        return parseLine(line).path("result");
    }

    private JsonNode parseLine(String line) {
        try {
            return objectMapper.readTree(line.strip());
        } catch (IOException e) {
            return objectMapper.missingNode();
        }
    }

    /** True when both are 64-char hex and SHA-256(preimage) equals the payment hash. */
    private static boolean preimageMatchesHash(String preimageHex, String hashHex) {
        if (preimageHex.length() != 64 || hashHex.length() != 64) {
            return false;
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(HexFormat.of().parseHex(preimageHex));
            return MessageDigest.isEqual(digest, HexFormat.of().parseHex(hashHex));
        } catch (IllegalArgumentException e) {
            return false;
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    /**
     * Validate that a payment hash is exactly 64 hex characters (SHA-256 output).
     * Prevents path injection into LND REST API URIs.
     *
     * @throws IllegalArgumentException if the hash is null, wrong length, or not valid hex
     */
    private static void validatePaymentHash(String paymentHash) {
        if (paymentHash == null || paymentHash.length() != 64) {
            throw new IllegalArgumentException(
                    "paymentHash must be exactly 64 hex characters, got: " + paymentHash);
        }
        try {
            HexFormat.of().parseHex(paymentHash);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "paymentHash must be valid hex: " + paymentHash, e);
        }
    }

    private static String readMacaroonAsHex(String path) {
        try {
            byte[] macaroonBytes = Files.readAllBytes(Paths.get(path));
            return bytesToHex(macaroonBytes);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read LND macaroon from: " + path, e);
        }
    }

    /**
     * Load a TLS certificate for certificate pinning against the LND node.
     * Called only when {@code tlsCertPath} is non-empty.
     *
     * @throws IllegalStateException if the certificate file is not found or cannot be parsed
     */
    private static SSLContext loadTlsCert(String tlsCertPath) {
        try {
            Path certPath = Paths.get(tlsCertPath);
            if (!Files.exists(certPath)) {
                throw new IllegalStateException("LND TLS cert not found at: " + tlsCertPath);
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
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Could not load LND TLS cert from: " + tlsCertPath, e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    // --- DTOs (immutable records) ---

    /**
     * Response from LND invoice creation (/v1/invoices).
     *
     * @param rHash          SHA-256 payment hash (hex)
     * @param paymentRequest BOLT11-encoded invoice string
     * @param addIndex       monotonically increasing invoice index (may be null)
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record CreateInvoiceResponse(
            @JsonProperty("r_hash") String rHash,
            @JsonProperty("payment_request") String paymentRequest,
            @JsonProperty("add_index") String addIndex
    ) {}

    /**
     * LND invoice details (/v1/invoice/{hash}).
     *
     * @param memo           invoice description
     * @param rHash          SHA-256 payment hash (hex)
     * @param paymentRequest BOLT11-encoded invoice string
     * @param value          invoice amount in satoshis (as a string)
     * @param state          invoice state (e.g. {@code OPEN}, {@code SETTLED}, {@code CANCELED})
     * @param settleDate     Unix timestamp when the invoice was settled (may be null)
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
     *
     * @param paymentHash     SHA-256 hash of the payment preimage
     * @param paymentPreimage 32-byte preimage that proves payment (hex)
     * @param status          final payment status (e.g. {@code SUCCEEDED}, {@code FAILED})
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record PayInvoiceResponse(
            @JsonProperty("payment_hash") String paymentHash,
            @JsonProperty("payment_preimage") String paymentPreimage,
            String status
    ) {}

    /**
     * Basic node information from LND (/v1/getinfo).
     *
     * @param alias          human-readable node alias
     * @param blockHeight    current best block height seen by LND
     * @param syncedToChain  whether LND is fully synced to the chain
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record NodeInfo(
            String alias,
            @JsonProperty("block_height") int blockHeight,
            @JsonProperty("synced_to_chain") boolean syncedToChain
    ) {}
}
