# lnurl-java

Java library for LNURL protocols — Bech32 encoding (LUD-01), LNURL-auth (LUD-04) Lightning wallet authentication, LNURL-pay (LUD-06) Lightning address resolution, and a LND REST client.

Verified compatible with Wallet of Satoshi and Aqua wallets.

> **Built to power [AskAHuman](https://askahuman.online)** — a human verification marketplace where AI agents pay via Lightning to get answers from real people. Platform launching soon.

## Modules

| Module | Purpose |
|--------|---------|
| `lnurl-java-core` | Pure Java — zero Spring, zero Lombok, zero Micrometer |
| `lnurl-java-spring-boot-starter` | Spring Boot autoconfiguration for all three protocols |
| `lnurl-java-examples` | Runnable Spring Boot demo app |

## Maven Dependencies

```xml
<!-- Core only (no Spring required) -->
<dependency>
    <groupId>online.askahuman</groupId>
    <artifactId>lnurl-java-core</artifactId>
    <version>0.4.0</version>
</dependency>

<!-- Spring Boot autoconfiguration -->
<dependency>
    <groupId>online.askahuman</groupId>
    <artifactId>lnurl-java-spring-boot-starter</artifactId>
    <version>0.4.0</version>
</dependency>
```

## Quickstart

### Bech32 Encoding (LUD-01)

```java
import online.askahuman.lnurl.Bech32Utils;

// Encode a callback URL for QR display
String callbackUrl = "https://example.com/auth/callback?tag=login&k1=abcdef...";
String lnurl = Bech32Utils.encodeLnurl(callbackUrl);
// → "LNURL1DP68GURN8GHJ7..." (uppercase, QR-optimised)
```

### LNURL-auth (LUD-04)

```java
import online.askahuman.lnurl.LnurlAuthService;
import online.askahuman.lnurl.Bech32Utils;

LnurlAuthService authService = new LnurlAuthService(300); // 300s challenge expiry

// Step 1: Generate a k1 challenge
String k1 = authService.generateChallenge();
String callbackUrl = "https://your.domain/auth/callback?tag=login&k1=" + k1;
String lnurl = Bech32Utils.encodeLnurl(callbackUrl);
// Display lnurl as QR code to the user

// Step 2: Discovery call — wallet hits callback without sig/key first
if (authService.isValidChallenge(k1)) {
    return Map.of("tag", "login", "k1", k1, "action", "login");
}

// Step 3: Auth call — wallet signs k1 and sends sig + key
boolean verified = authService.verifyCallback(k1, sig, key);
if (verified) {
    String linkingKey = authService.consumeAndGetKey(k1); // atomic consume
    // Issue JWT for linkingKey
}

// Cleanup (call periodically, or use Spring Boot starter for auto-scheduling)
authService.cleanupExpiredChallenges();
```

### LNURL-pay (LUD-06) — Lightning Address Resolution

```java
import online.askahuman.lnurl.LnurlPayClient;

// Create client (strict mode: throws on resolution failure)
LnurlPayClient client = LnurlPayClient.create(true);

// Resolve a Lightning address to a BOLT11 invoice
String invoice = client.resolveLightningAddress("alice@getalby.com", 1000); // 1000 sats
// Pay `invoice` via Lightning

// Development mode: returns a mock invoice when the provider cannot be reached or resolved,
// instead of throwing (a refused invoice, see below, still throws)
LnurlPayClient devClient = LnurlPayClient.create(false);
```

#### Invoice validation (LUD-06 step 7)

The provider that answers the invoice request is not trusted. Before returning the `pr` invoice,
`resolveLightningAddress` checks that it is a well-formed, checksum-valid BOLT11 invoice, carries an
amount, asks for **exactly** the requested amount (compared in millisatoshis) and has not expired.
Otherwise it throws `LnurlInvoiceRejectedException` (see `getReason()`), in both strict and
development mode: a refused invoice is never replaced by a mock invoice.

Not checked by the library, because they are policy for the application: the network (mainnet,
testnet, ...) the invoice is for and a minimum remaining validity. The invoice signature is not
verified either; pay the returned invoice with a node that does, so the amount that was checked is
the amount that is paid.

The description hash (`h` tag) is not checked: the current LUD-06 text no longer requires it, and a
malicious provider controls both the metadata and the hash anyway.

> **Behaviour change:** providers whose invoices do not match the requested amount, or that return
> an unparseable `pr`, used to be accepted and are now refused.

### LND REST Client

```java
import online.askahuman.lnurl.lnd.LndClient;
import online.askahuman.lnurl.lnd.PaymentFailedException;
import online.askahuman.lnurl.lnd.PaymentOutcomeUnknownException;
import online.askahuman.lnurl.lnd.PaymentTrackResult;

// Connect to LND (reads macaroon file, configures TLS)
LndClient lnd = LndClient.withMacaroonFile(
    "localhost", 8080,
    "/path/to/admin.macaroon",
    "/path/to/tls.cert"
);

// Create invoice
LndClient.CreateInvoiceResponse invoice = lnd.createInvoice(1000L, "Payment memo", 3600L);
String paymentRequest = invoice.paymentRequest();
String paymentHash    = invoice.rHash();

// Check payment status
boolean paid = lnd.isInvoicePaid(paymentHash);

// Pay an invoice (V2 router API). Returns only for a confirmed, verified payment.
try {
    LndClient.PayInvoiceResponse payment = lnd.payInvoice(paymentRequest);
    System.out.println(payment.paymentPreimage()); // proof of payment; hashes to payment.paymentHash()
} catch (PaymentFailedException e) {
    // LND confirmed the payment failed. Nothing was sent; paying again is safe.
    System.out.println(e.getFailureReason());
} catch (PaymentOutcomeUnknownException e) {
    // Timeout, dropped connection, still in flight, or an unrecognised answer. The payment
    // may still settle: look it up before paying anything else.
    PaymentTrackResult state = lnd.trackPayment(paymentHash); // SUCCEEDED, FAILED, IN_FLIGHT or NOT_INITIATED
}

// Graceful degradation (development only, no macaroon configured): LndClient falls back to
// mock mode when LND is unreachable. Mock invoices are considered "paid" after 5 seconds.
System.out.println(lnd.isConnected()); // false in mock mode
```

#### Payment outcomes

`payInvoice` distinguishes four cases, and treats anything it cannot positively classify as
unknown rather than as a success or a failure:

| Result | Meaning |
|--------|---------|
| returns | LND reported `SUCCEEDED` and the preimage hashes to the payment hash |
| `PaymentFailedException` | LND confirmed the failure (`getFailureReason()` is a code, never gateway text) |
| `PaymentOutcomeUnknownException` | HTTP timeout, dropped connection, `IN_FLIGHT`, error body, 5xx, or an unrecognised status |
| `LnurlException` (plain) | the request provably never reached LND's router: connection refused or timed out, TLS handshake failed, HTTP 400/401/403 |

The HTTP call has a connect timeout (10 s) and a request deadline (75 s) beyond LND's own 60 s
attempt timeout, so a stalled node cannot block the caller indefinitely. `trackPayment` reads
only the first state LND reports (`GET /v2/router/track/{hash}`), so it returns promptly for a
payment still in flight. `NOT_INITIATED` means LND has no record of the payment.

> **Behaviour change:** `payInvoice` used to treat every status other than `FAILED` as success
> (including `IN_FLIGHT` and error bodies), had no HTTP deadline, and returned a mock success
> for a `FAILED` payment on a non-strict client. It is now strict as described above, and
> `FAILED` always throws.

### Spring Boot autoconfiguration

Add the starter dependency and configure `application.yml`:

```yaml
lnurl:
  auth:
    challenge-expiry-seconds: 300
  lnd:
    host: localhost
    rest-port: 8080
    macaroon-path: /path/to/admin.macaroon
    tls-cert-path: /path/to/tls.cert
```

The starter auto-creates `LnurlAuthService`, `LnurlPayClient`, and `LndClient` beans.
`LnurlAuthService.cleanupExpiredChallenges()` is automatically scheduled every 60 seconds.

## Wallet Compatibility

Verified with real wallets (February 2026):

| Wallet | LNURL-auth | LNURL-pay |
|--------|-----------|-----------|
| Wallet of Satoshi (WoS) | ✅ | ✅ |
| Aqua | ✅ | — |

## Critical Implementation Notes

### LNURL-auth Signature Algorithm

**Always use `NONEwithECDSA`** (BouncyCastle), never `SHA256withECDSA`.

k1 is a 32-byte random challenge. Wallets pass it directly as the pre-hashed message to secp256k1.
Using `SHA256withECDSA` would double-hash k1, causing all signature verifications to fail silently.

```java
// Correct — matches how wallets sign:
Signature.getInstance("NONEwithECDSA", "BC");

// WRONG — double-hashes k1, all verifications fail:
Signature.getInstance("SHA256withECDSA", "BC");
```

### Bech32 Output is Uppercase

`Bech32Utils.encodeLnurl()` returns the LNURL string in UPPERCASE (`LNURL1...`). This is required for efficient QR alphanumeric encoding. Wallets that expect lowercase will not recognise the QR code.

### Two-step Callback Flow

LNURL-auth wallets make two requests to your callback URL:

1. **Discovery call** — no `sig` or `key` params. Return: `{"tag":"login","k1":"...","action":"login"}`
2. **Auth call** — includes `sig` and `key`. Verify the signature, then issue a JWT.

Use `isValidChallenge(k1)` to distinguish between the two steps.

### Bech32 Encoding — `tag=login` Must Be in the URL

The `tag=login` parameter must be in the callback URL query string **before** Bech32 encoding, not just in the JSON response. Some wallets validate the decoded URL.

```java
// Correct:
String callbackUrl = baseUrl + "/auth/callback?tag=login&k1=" + k1;
String lnurl = Bech32Utils.encodeLnurl(callbackUrl);

// Wrong — tag not in URL:
String callbackUrl = baseUrl + "/auth/callback?k1=" + k1;
```

### LNURL-pay Callback URL Separator

Per LUD-06, if the callback URL already contains query parameters, append `&amount=` (not `?amount=`). This library handles this automatically.

### SSRF Protection in LnurlPayClient

`resolveLightningAddress()` validates the Lightning address domain and callback URL to prevent Server-Side Request Forgery:

- Domain must not contain `:`, `/`, `?`, `#` (no ports, no paths, no query strings)
- Callback URL scheme must be `https://`

Attempting to resolve `alice@evil.com:9200` or a callback with `http://` will throw `IllegalArgumentException` / `RuntimeException`.

## Security Notes

- **Macaroon files**: store admin macaroons with `chmod 600`; never commit them to version control
- **Challenge expiry**: default 300 seconds; use shorter values in production if tolerable for UX
- **`consumeAndGetKey()`**: atomically removes the challenge, preventing race conditions where two concurrent callers could both claim the same authenticated session
- **Mock mode**: `LndClient` and `LnurlPayClient` fall back to mock data when LND is unavailable in development; always configure a macaroon (strict `LndClient`) and `failOnResolutionError=true` in production

## License

Apache License 2.0 — see [LICENSE](LICENSE).
