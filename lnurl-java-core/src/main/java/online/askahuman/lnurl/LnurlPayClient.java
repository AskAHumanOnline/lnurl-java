package online.askahuman.lnurl;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Client for resolving Lightning addresses to BOLT11 invoices using the LNURL-pay protocol (LUD-06).
 *
 * <p>LNURL-pay Protocol Flow:</p>
 * <ol>
 *   <li>Parse Lightning address (e.g., "alice@getalby.com")</li>
 *   <li>Fetch LNURL endpoint: GET https://getalby.com/.well-known/lnurlp/alice</li>
 *   <li>Parse response with callback URL, min/max amounts</li>
 *   <li>Request invoice: GET {callback}?amount={millisats}</li>
 *   <li>Parse response with BOLT11 invoice</li>
 * </ol>
 *
 * <p>This is a pure Java implementation with no Spring dependencies.
 * Uses {@link java.net.http.HttpClient} for HTTP calls and Jackson for JSON parsing.</p>
 */
public class LnurlPayClient implements AutoCloseable {

    private static final System.Logger log = System.getLogger(LnurlPayClient.class.getName());

    private final HttpClient httpClient;
    private final boolean failOnResolutionError;
    private final ObjectMapper objectMapper;

    /**
     * Create a new LNURL-pay client with the given HttpClient.
     *
     * @param httpClient             the HTTP client to use for LNURL-pay requests
     * @param failOnResolutionError  if true, resolution failures throw RuntimeException;
     *                               if false, a mock invoice is returned instead
     */
    public LnurlPayClient(HttpClient httpClient, boolean failOnResolutionError) {
        this.httpClient = httpClient;
        this.failOnResolutionError = failOnResolutionError;
        this.objectMapper = new ObjectMapper();
        this.objectMapper.deactivateDefaultTyping();
        log.log(System.Logger.Level.INFO,
                "LnurlPayClient initialized (fail-on-resolution-error: {0})",
                failOnResolutionError);
    }

    /**
     * Factory method that creates a LnurlPayClient with a default 10-second timeout HttpClient.
     *
     * @param failOnResolutionError if true, resolution failures throw RuntimeException
     * @return a new LnurlPayClient instance
     */
    public static LnurlPayClient create(boolean failOnResolutionError) {
        HttpClient httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        return new LnurlPayClient(httpClient, failOnResolutionError);
    }

    /**
     * Resolve a Lightning address to a BOLT11 invoice using the LNURL-pay protocol.
     *
     * @param lightningAddress Lightning address in format "username@domain.com"
     * @param amountSats       payout amount in satoshis (must be &gt; 0)
     * @return BOLT11 invoice string (or mock invoice if resolution fails and failOnResolutionError=false)
     * @throws IllegalArgumentException if the address format is invalid, the amount is &lt;= 0,
     *                                  or the amount falls outside provider limits
     * @throws RuntimeException         if resolution fails and failOnResolutionError=true
     */
    public String resolveLightningAddress(String lightningAddress, long amountSats) {
        try {
            // Validate amount before any network activity
            if (amountSats <= 0) {
                throw new IllegalArgumentException(
                        "amountSats must be greater than 0, got: " + amountSats);
            }

            log.log(System.Logger.Level.DEBUG,
                    "Resolving Lightning address: {0} for {1} sats", lightningAddress, amountSats);

            // Step 1: Parse Lightning address
            String[] parts = lightningAddress.split("@");
            if (parts.length != 2) {
                throw new IllegalArgumentException(
                        "Invalid Lightning address format: must be username@domain.com");
            }
            String username = parts[0];
            String domain = parts[1];

            // Validate username and domain to prevent SSRF (LUD-06 § 1)
            if (username.isEmpty() || username.contains("/") || username.contains("?")
                    || username.contains("#") || username.contains("@")) {
                throw new IllegalArgumentException(
                        "Invalid Lightning address: username contains illegal characters");
            }
            if (domain.isEmpty() || domain.contains("/") || domain.contains("?")
                    || domain.contains("#") || domain.contains(":")) {
                throw new IllegalArgumentException(
                        "Invalid Lightning address: domain contains illegal characters (bare domain required)");
            }
            // H-02: Reject private/loopback/link-local IP literals as provider domain
            validateNotPrivateIpLiteral(domain);

            // Step 2: Fetch LNURL-pay endpoint
            String lnurlEndpoint = "https://" + domain + "/.well-known/lnurlp/" + username;
            log.log(System.Logger.Level.DEBUG, "Fetching LNURL endpoint: {0}", lnurlEndpoint);

            HttpRequest endpointRequest = HttpRequest.newBuilder()
                    .uri(URI.create(lnurlEndpoint))
                    .timeout(Duration.ofSeconds(10))
                    .GET()
                    .build();
            HttpResponse<String> endpointResponse = httpClient.send(
                    endpointRequest, HttpResponse.BodyHandlers.ofString());

            if (endpointResponse.statusCode() != 200) {
                throw new RuntimeException(
                        "LNURL-pay endpoint returned HTTP " + endpointResponse.statusCode());
            }

            LnurlPayEndpoint endpoint = objectMapper.readValue(
                    endpointResponse.body(), LnurlPayEndpoint.class);

            if (endpoint == null || endpoint.getCallback() == null) {
                throw new RuntimeException("Invalid LNURL-pay endpoint response");
            }

            // Validate tag
            if (!"payRequest".equals(endpoint.getTag())) {
                throw new RuntimeException(
                        "Invalid LNURL-pay tag: expected 'payRequest', got '" + endpoint.getTag() + "'");
            }

            // Step 3: Validate amount against provider limits
            long amountMillisats = amountSats * 1000L;
            if (amountMillisats < endpoint.getMinSendable()) {
                throw new IllegalArgumentException(
                        "Amount " + amountSats + " sats (" + amountMillisats +
                                " msats) below minimum: " + endpoint.getMinSendable() + " msats");
            }
            if (amountMillisats > endpoint.getMaxSendable()) {
                throw new IllegalArgumentException(
                        "Amount " + amountSats + " sats (" + amountMillisats +
                                " msats) above maximum: " + endpoint.getMaxSendable() + " msats");
            }

            // Validate callback URL scheme to prevent SSRF
            URI callbackUri = URI.create(endpoint.getCallback());
            if (callbackUri.getScheme() == null || !callbackUri.getScheme().equals("https")) {
                throw new RuntimeException("LNURL-pay callback URL must use HTTPS scheme");
            }
            // H-01: Callback host must match (or be a subdomain of) the provider domain
            String callbackHost = callbackUri.getHost();
            if (!isAllowedCallbackDomain(callbackHost, domain)) {
                throw new RuntimeException(
                        "LNURL-pay callback host '" + callbackHost +
                        "' does not match provider domain '" + domain + "'");
            }
            // H-02: Reject private/loopback/link-local IP literals in callback URL
            validateNotPrivateIpLiteral(callbackHost);

            // Step 4: Request invoice — use & if callback already has query params (LUD-06 § 5)
            String separator = endpoint.getCallback().contains("?") ? "&" : "?";
            String invoiceUrl = endpoint.getCallback() + separator + "amount=" + amountMillisats;
            log.log(System.Logger.Level.DEBUG, "Requesting invoice: {0}", invoiceUrl);

            HttpRequest invoiceRequest = HttpRequest.newBuilder()
                    .uri(URI.create(invoiceUrl))
                    .timeout(Duration.ofSeconds(10))
                    .GET()
                    .build();
            HttpResponse<String> invoiceResponse = httpClient.send(
                    invoiceRequest, HttpResponse.BodyHandlers.ofString());

            if (invoiceResponse.statusCode() != 200) {
                throw new RuntimeException(
                        "LNURL-pay invoice endpoint returned HTTP " + invoiceResponse.statusCode());
            }

            LnurlPayInvoiceResponse invoiceResult = objectMapper.readValue(
                    invoiceResponse.body(), LnurlPayInvoiceResponse.class);

            if (invoiceResult == null || invoiceResult.getPr() == null) {
                throw new RuntimeException("Invalid LNURL-pay invoice response");
            }

            log.log(System.Logger.Level.INFO,
                    "Successfully resolved Lightning address {0} to invoice", lightningAddress);
            return invoiceResult.getPr();

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("LNURL-pay request interrupted", e);
        } catch (IllegalArgumentException e) {
            // Input validation failures always propagate — not swallowed by lenient mode
            throw e;
        } catch (Exception e) {
            return handleResolutionError(lightningAddress, amountSats, e);
        }
    }

    @Override
    public void close() {
        httpClient.close();
    }

    /** Returns true if {@code callbackHost} equals or is a subdomain of {@code providerDomain}. */
    private static boolean isAllowedCallbackDomain(String callbackHost, String providerDomain) {
        if (callbackHost == null || providerDomain == null) return false;
        String h = callbackHost.toLowerCase();
        String p = providerDomain.toLowerCase();
        return h.equals(p) || h.endsWith("." + p);
    }

    /**
     * Rejects IPv4 literals that fall in private, loopback, or link-local ranges (SSRF guard).
     * Hostname strings (e.g. "example.com") pass through without DNS resolution.
     */
    private static void validateNotPrivateIpLiteral(String host) {
        if (host == null) return;
        // Check for IPv6 loopback (::1)
        if (host.contains(":")) {
            if ("::1".equals(host) || "0:0:0:0:0:0:0:1".equals(host)) {
                throw new IllegalArgumentException(
                        "LNURL-pay URL points to a private/reserved IP address: " + host);
            }
            return; // Other IPv6 addresses treated as public
        }
        // Check for IPv4 literal (four dotted decimal groups)
        String[] parts = host.split("\\.", -1);
        if (parts.length != 4) return;
        try {
            int[] o = new int[4];
            for (int i = 0; i < 4; i++) {
                o[i] = Integer.parseInt(parts[i]);
                if (o[i] < 0 || o[i] > 255) return; // Not a valid IP literal
            }
            if (o[0] == 127                                         // 127.0.0.0/8 loopback
                    || o[0] == 10                                   // 10.0.0.0/8 private
                    || (o[0] == 172 && o[1] >= 16 && o[1] <= 31)   // 172.16.0.0/12 private
                    || (o[0] == 192 && o[1] == 168)                 // 192.168.0.0/16 private
                    || (o[0] == 169 && o[1] == 254)                 // 169.254.0.0/16 link-local
                    || o[0] == 0) {                                 // 0.0.0.0/8 reserved
                throw new IllegalArgumentException(
                        "LNURL-pay URL points to a private/reserved IP address: " + host);
            }
        } catch (NumberFormatException e) {
            // Parts are not integers — not a valid IPv4 literal, treat as hostname
        }
    }

    private String handleResolutionError(String lightningAddress, long amountSats, Exception e) {
        log.log(System.Logger.Level.WARNING,
                "LNURL-pay resolution failed for {0}: {1}", lightningAddress, e.getMessage());

        if (!failOnResolutionError) {
            String mockInvoice = "mock_invoice_" + lightningAddress + "_" + amountSats;
            log.log(System.Logger.Level.WARNING,
                    "Returning mock invoice (fail-on-resolution-error=false): {0}", mockInvoice);
            return mockInvoice;
        } else {
            throw new RuntimeException("Lightning address resolution failed: " + e.getMessage(), e);
        }
    }

    /**
     * LNURL-pay endpoint response (step 2).
     * See: <a href="https://github.com/lnurl/luds/blob/luds/06.md">LUD-06</a>
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class LnurlPayEndpoint {
        @JsonProperty("callback")
        private String callback;

        @JsonProperty("minSendable")
        private long minSendable;

        @JsonProperty("maxSendable")
        private long maxSendable;

        @JsonProperty("metadata")
        private String metadata;

        @JsonProperty("tag")
        private String tag;

        public LnurlPayEndpoint() {}

        public String getCallback() { return callback; }
        public void setCallback(String callback) { this.callback = callback; }

        public long getMinSendable() { return minSendable; }
        public void setMinSendable(long minSendable) { this.minSendable = minSendable; }

        public long getMaxSendable() { return maxSendable; }
        public void setMaxSendable(long maxSendable) { this.maxSendable = maxSendable; }

        public String getMetadata() { return metadata; }
        public void setMetadata(String metadata) { this.metadata = metadata; }

        public String getTag() { return tag; }
        public void setTag(String tag) { this.tag = tag; }
    }

    /**
     * LNURL-pay invoice response (step 4).
     * See: <a href="https://github.com/lnurl/luds/blob/luds/06.md">LUD-06</a>
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class LnurlPayInvoiceResponse {
        @JsonProperty("pr")
        private String pr;

        public LnurlPayInvoiceResponse() {}

        public String getPr() { return pr; }
        public void setPr(String pr) { this.pr = pr; }
    }
}
