# Security & Code Review Audit — lnurl-java

**Audit Date:** 2026-02-26
**Branch:** `chore/AAH-0001-code-security-audit`
**Scope:** Full pre-release review before Maven Central publication

---

## Summary

| Severity | Count |
|----------|-------|
| BLOCKER (Code Quality) | 5 |
| CRITICAL (Security) | 4 |
| HIGH (Security) | 5 |
| MAJOR (Code Quality) | 7 |
| MEDIUM (Security) | 7 |
| MINOR / LOW | 14 |

---

## BLOCKER Issues (Code Review)

### B-1: Examples module will be published to Maven Central
**File:** `lnurl-java-examples/pom.xml`

Missing `<maven.deploy.skip>true</maven.deploy.skip>`. The examples fat JAR would be uploaded to Maven Central, polluting the namespace.

**Fix:** Add `<maven.deploy.skip>true</maven.deploy.skip>` to examples properties.

---

### B-2: LnurlPayClient and LndClient not AutoCloseable — resource leak
**Files:** `LnurlPayClient.java:59-64`, `LndClient.java:87`

`HttpClient` (Java 21+) implements `AutoCloseable`. Neither `LnurlPayClient` nor `LndClient` implement `AutoCloseable`, causing thread pool and connection leaks when instances are discarded.

**Fix:** Implement `AutoCloseable` on both classes and delegate `close()` to the underlying `HttpClient`.

---

### B-3: `amountSats` parameter should be `long`; no negative value validation
**File:** `LnurlPayClient.java:126`

`int amountSats` limits amounts to ~21.47 BTC. No validation that `amountSats >= 0` — negative values pass through silently.

**Fix:** Change parameter type to `long`, add `if (amountSats <= 0) throw new IllegalArgumentException(...)`.

---

### B-4: Path injection in LndClient via unvalidated `paymentHash`
**File:** `LndClient.java:201, 261`

```java
.uri(URI.create(baseUrl + "/v1/invoice/" + paymentHash))
```

No validation on `paymentHash` — path traversal characters could invoke arbitrary LND REST endpoints, potentially leading to fund theft.

**Fix:** Validate `paymentHash` matches `^[0-9a-fA-F]{64}$` before URI construction.

---

### B-5: LND admin macaroon stored as cleartext `String`
**File:** `LndClient.java:56`

Immutable `String` persists in heap (heap dumps expose full admin macaroon). `withMacaroonFile()` also silently falls back to `"dummy_macaroon_for_testing"` on any file read failure.

**Fix:** Fail fast (throw exception) when macaroon file cannot be read. Document heap dump protection requirement.

---

## CRITICAL Security Findings

### C-01: LNURL-auth challenge replay — `verifyCallback()` has no single-use enforcement
**File:** `LnurlAuthService.java:87-129`

After successful signature verification, the challenge is updated in the map but NOT removed. The same `(k1, sig, key)` tuple can be replayed repeatedly until challenge expiry (300s default). An attacker who captures a valid tuple can re-authenticate as the victim.

```java
// Challenge updated but NOT removed after successful verification
challenges.put(k1, new AuthChallenge(k1, challenge.expiresAt(), key));
```

**Fix:** After successful `verifyCallback()`, mark the challenge as verified (e.g., add a `verified` flag to `AuthChallenge`) and reject subsequent `verifyCallback()` calls for the same k1.

---

### C-02: Path injection in LndClient via `paymentHash` (fund theft risk)
*(Same as B-4 — classified Critical due to fund loss potential)*

**CVSS:** 9.1 — An attacker who controls `paymentHash` input can invoke arbitrary LND REST endpoints.

---

### C-03: LND admin macaroon cleartext in heap memory
*(Same as B-5 — classified Critical due to fund loss potential)*

**CVSS:** 7.5 — Heap dump exposure leads to complete Lightning node compromise.

---

### C-04: Silent mock mode fallback in production — fake payment acceptance
**File:** `LndClient.java:100-123, 133-161, 197-220, 302-333`

Every LND API method silently falls back to mock mode on any exception. Mock invoices are marked as "paid" after 5 seconds. In production, a temporary LND outage causes the application to accept fake payments and deliver goods/services without real payment.

**Fix:** Add a `strictMode` constructor parameter (default `true`) that throws exceptions instead of falling back to mock mode. Spring auto-configuration should default to strict mode.

---

## HIGH Security Findings

### H-01: Callback URL domain not validated against LNURL endpoint domain
**File:** `LnurlPayClient.java:138-153`

A compromised LNURL endpoint can return a callback URL pointing to an attacker-controlled server. Only HTTPS scheme is validated, not domain matching.

**Fix:** Validate callback URL domain matches the original `domain` from the Lightning address.

---

### H-02: No private IP SSRF protection for callback URL
**File:** `LnurlPayClient.java:138-153`

Callback URL can point to RFC 1918 addresses (10.x, 172.16.x, 192.168.x), loopback, or cloud metadata endpoints (169.254.169.254). The library would faithfully make requests to these internal hosts.

**Fix:** Resolve callback hostname and block private/loopback/link-local ranges.

---

### H-03: Negative amount allows bypassing payment amount validation
*(Same as B-3)*

**Fix:** Validate `amountSats > 0`.

---

### H-04: TLS certificate load failure silently falls back to system trust store
**File:** `LndClient.java:114-122`

When a TLS cert path is configured but the file cannot be loaded, the code silently uses the system trust store. This nullifies certificate pinning, enabling MITM against the LND REST API.

**Fix:** When `tlsCertPath` is non-empty but the cert cannot be loaded, throw an exception rather than silently falling back.

---

### H-05: k1 challenge value logged at WARNING level — credential leakage
**File:** `LnurlAuthService.java:91, 95, 101, 119`

The k1 authentication token is logged at WARNING level in production log systems. An attacker with log access can replay authentication tokens.

**Fix:** Truncate k1 in log messages (log first 8 chars + `...`).

---

## MAJOR Code Quality Issues

### M-1: Challenge map unbounded — DoS via memory exhaustion in standalone mode
**File:** `LnurlAuthService.java:29`

No maximum size on `ConcurrentHashMap`. An attacker flooding `generateChallenge()` could cause OOM before the 60s cleanup runs.

**Fix:** Add a maximum challenge count (e.g., 10,000) and reject new challenges when at capacity.

---

### M-2: `withMacaroonFile()` silently degrades to dummy credentials
**File:** `LndClient.java:101-111`

File read failure causes silent fallback to `"dummy_macaroon_for_testing"`. Every LND call then fails with auth errors, masking the real cause (misconfigured path).

**Fix:** Throw `IllegalStateException` when macaroon file cannot be read.

---

### M-3: Input validation exceptions swallowed in lenient mode
**File:** `LnurlPayClient.java:168-173`

Broad `catch (Exception e)` swallows `IllegalArgumentException` from SSRF validators when `failOnResolutionError = false`. Invalid inputs like `"alice@evil.com:8080"` silently return mock invoices.

**Fix:** Separate input validation exceptions from network/resolution exceptions. Always propagate `IllegalArgumentException`.

---

### M-4: Thread interrupt after mock fallback — broken shutdown semantics
**File:** `LnurlPayClient.java:168-170`, `LndClient.java:156-158, 214-216`

After restoring interrupt flag, code returns mock data instead of propagating interruption. Shutdown signals produce fake results.

**Fix:** After `Thread.currentThread().interrupt()`, re-throw as `RuntimeException` wrapping the `InterruptedException`.

---

### M-5: No Bech32 decoding — incomplete LUD-01 implementation
**File:** `Bech32Utils.java`

Only encoding is implemented. Consumers who receive LNURLs need a separate library to decode them. LUD-01 requires both.

**Fix:** Implement `decodeLnurl(String encoded)` → `String url`.

---

### M-6: No HTTP response status code validation before JSON parsing
**Files:** `LnurlPayClient.java:109-113`, `LndClient.java:148-149`

HTTP 404/500/redirect responses cause confusing Jackson parse exceptions instead of clear error messages.

**Fix:** Check `response.statusCode() == 200` before parsing; throw descriptive exception otherwise.

---

### M-7: `@EnableScheduling` in auto-configuration has application-wide effect
**File:** `LnurlAuthAutoConfiguration.java:29`

A Spring Boot starter should not globally enable scheduling; it may conflict with the consumer's custom `TaskScheduler`.

**Fix:** Use `@ConditionalOnBean(TaskScheduler.class)` or create a dedicated `TaskScheduler` bean scoped to cleanup only.

---

## MEDIUM / MINOR Issues (Track for subsequent releases)

- **M-SEC-01:** Callback redirect policy not documented (no-redirect is secure but should be explicit)
- **M-SEC-02:** No rate limiting guidance for `verifyCallback()` (CPU DoS via repeated ECDSA)
- **M-SEC-03:** Signature length range 140-144 too narrow; DER ECDSA can be 134-146 chars
- **M-SEC-04:** `Bech32Utils.encodeLnurl()` accepts HTTP URLs without warning
- **M-SEC-05:** Jackson ObjectMapper missing `deactivateDefaultTyping()` (defense-in-depth)
- **m-1:** `javadoc` plugin `failOnError=false` in parent POM — should be `true` before release
- **m-2:** BouncyCastle registered in static initializer (global JVM state side effect)
- **m-3:** `new SecureRandom()` per mock invoice creation — should be a reused field
- **m-4:** No custom exception hierarchy — `RuntimeException` thrown throughout
- **m-5:** `LnurlProperties.Lnd.restPort` defaults to 8080, conflicts with Spring Boot default
- **m-6:** Missing `@Nullable` annotations on nullable return values
- **m-7:** No OWASP dependency-check in CI/CD pipeline
- **m-8:** Examples application.yml base URL uses HTTP without production warning

---

## Good Patterns (Keep)

- `NONEwithECDSA` — correct algorithm for k1 (no pre-hashing)
- `computeIfPresent()` — atomic challenge consumption
- `SecureRandom` 32-byte challenge generation
- SSRF protection on `.well-known` requests (character blacklist)
- HTTPS enforcement on callback URLs
- `MAX_MOCK_PAYMENT_ENTRIES` bound on mock payment map
- `@ConditionalOnMissingBean` pattern in all auto-configurations
- GPG signing + `autoPublish: false` for Maven Central
- 89 tests, 80% JaCoCo coverage gate

---

## Recommended Fix Order (Before Maven Central Release)

1. **B-1** — `maven.deploy.skip` in examples POM (5 min)
2. **B-4 / C-02** — `paymentHash` hex validation in LndClient (10 min)
3. **C-01** — Challenge single-use enforcement in `verifyCallback()` (20 min)
4. **C-04** — `strictMode` flag in LndClient (30 min)
5. **B-5 / C-03** — Fail fast when macaroon file unreadable (15 min)
6. **H-04** — Fail fast when TLS cert path configured but unreadable (10 min)
7. **H-05** — Truncate k1 in log messages (5 min)
8. **B-3 / H-03** — `long amountSats`, add `> 0` validation (10 min)
9. **M-3** — Separate input validation from resolution errors (15 min)
10. **M-6** — HTTP status code checks before JSON parsing (15 min)
11. **M-7** — `@EnableScheduling` scope fix (20 min)
12. **B-2** — `AutoCloseable` on LnurlPayClient and LndClient (20 min)
13. **H-01** — Callback domain matching (15 min)
14. **H-02** — Private IP SSRF protection for callback URL (30 min)
15. **M-1** — Challenge map size cap (10 min)
