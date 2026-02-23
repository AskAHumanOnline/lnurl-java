# lnurl-java

Java library for LNURL protocols — Bech32 encoding (LUD-01), LNURL-auth (LUD-04) Lightning wallet authentication, LNURL-pay (LUD-06) Lightning address resolution, and a LND REST client.

Verified compatible with Wallet of Satoshi and Aqua wallets.

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
    <version>0.1.0</version>
</dependency>

<!-- Spring Boot autoconfiguration -->
<dependency>
    <groupId>online.askahuman</groupId>
    <artifactId>lnurl-java-spring-boot-starter</artifactId>
    <version>0.1.0</version>
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

// Development mode: returns mock invoice on failure instead of throwing
LnurlPayClient devClient = LnurlPayClient.create(false);
```

### LND REST Client

```java
import online.askahuman.lnurl.lnd.LndClient;

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

// Pay an invoice (V2 router API)
LndClient.PayInvoiceResponse payment = lnd.payInvoice(paymentRequest);
System.out.println(payment.status()); // SUCCEEDED, FAILED, or MOCK (mock mode)

// Graceful degradation: LndClient falls back to mock mode when LND is unavailable.
// Mock invoices are considered "paid" after 5 seconds.
System.out.println(lnd.isConnected()); // false in mock mode
```

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
- **Mock mode**: `LndClient` and `LnurlPayClient` fall back gracefully when LND is unavailable; disable mock mode (`failOnResolutionError=true`) in production

## License

Apache License 2.0 — see [LICENSE](LICENSE).
