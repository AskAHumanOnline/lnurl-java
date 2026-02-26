package online.askahuman.lnurl;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import java.security.*;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * LNURL-auth (LUD-04) challenge-response authentication service.
 *
 * <p>Manages k1 challenges, verifies secp256k1 ECDSA signatures from Lightning wallets,
 * and tracks authenticated linking keys. Thread-safe for concurrent use.</p>
 *
 * <p>This is a pure Java implementation with no Spring dependencies. For Spring Boot
 * auto-configuration (including scheduled cleanup), use the {@code lnurl-java-spring-boot-starter}.</p>
 */
public class LnurlAuthService {

    private static final System.Logger log = System.getLogger(LnurlAuthService.class.getName());

    private final Map<String, AuthChallenge> challenges = new ConcurrentHashMap<>();
    private final SecureRandom secureRandom = new SecureRandom();
    private final int challengeExpirySeconds;

    static {
        // Register Bouncy Castle provider for secp256k1 support (idempotent)
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Create a new LNURL-auth service.
     *
     * @param challengeExpirySeconds how long k1 challenges remain valid (seconds)
     */
    public LnurlAuthService(int challengeExpirySeconds) {
        this.challengeExpirySeconds = challengeExpirySeconds;
    }

    /**
     * Represents a k1 challenge with its expiry and optional linking key.
     *
     * @param k1         hex-encoded 32-byte challenge
     * @param expiresAt  when this challenge expires
     * @param linkingKey the wallet's compressed public key (hex), null until authenticated
     * @param verified   true once a valid signature has been accepted; prevents replay attacks
     */
    public record AuthChallenge(String k1, Instant expiresAt, String linkingKey, boolean verified) {
        // linkingKey is null until the wallet responds; verified prevents replay of the same (k1, sig, key) tuple
    }

    /**
     * Generate a new k1 challenge for LNURL-auth.
     *
     * @return hex-encoded 32-byte random k1 value
     */
    public String generateChallenge() {
        byte[] k1Bytes = new byte[32];
        secureRandom.nextBytes(k1Bytes);
        String k1 = HexFormat.of().formatHex(k1Bytes);

        challenges.put(k1, new AuthChallenge(k1, Instant.now().plusSeconds(challengeExpirySeconds), null, false));
        log.log(System.Logger.Level.DEBUG, "Generated LNURL-auth challenge: {0}", k1);
        return k1;
    }

    /**
     * Verify the LNURL-auth callback from a Lightning wallet.
     * Performs full secp256k1 signature verification per LNURL-auth spec:
     * - k1: 32-byte challenge (hex-encoded)
     * - sig: DER-encoded ECDSA signature (hex-encoded)
     * - key: 33-byte compressed secp256k1 public key (hex-encoded)
     *
     * @param k1  the challenge value (64 hex chars)
     * @param sig the hex-encoded DER signature
     * @param key the hex-encoded compressed public key (66 hex chars)
     * @return true if the signature is valid
     */
    public boolean verifyCallback(String k1, String sig, String key) {
        AuthChallenge challenge = challenges.get(k1);
        if (challenge == null) {
            log.log(System.Logger.Level.WARNING, "Challenge not found for k1: {0}...", truncate(k1));
            return false;
        }
        if (Instant.now().isAfter(challenge.expiresAt())) {
            challenges.remove(k1);
            log.log(System.Logger.Level.WARNING, "Challenge expired for k1: {0}...", truncate(k1));
            return false;
        }
        // Prevent replay: once a valid signature has been accepted, reject further attempts
        if (challenge.verified()) {
            log.log(System.Logger.Level.WARNING, "Challenge already verified (replay attempt) for k1: {0}...", truncate(k1));
            return false;
        }

        // Validate input format
        if (sig == null || sig.isEmpty() || sig.length() < 140 || sig.length() > 144 || key == null || key.length() != 66) {
            log.log(System.Logger.Level.WARNING, "Invalid sig or key format for k1: {0}... (key must be 66 hex chars)", truncate(k1));
            return false;
        }

        try {
            // Decode hex inputs
            byte[] k1Bytes = HexFormat.of().parseHex(k1);
            byte[] sigBytes = HexFormat.of().parseHex(sig);
            byte[] keyBytes = HexFormat.of().parseHex(key);

            // Verify signature using secp256k1
            if (!verifySecp256k1Signature(k1Bytes, sigBytes, keyBytes)) {
                log.log(System.Logger.Level.WARNING, "Signature verification failed for k1: {0}...", truncate(k1));
                return false;
            }

            // Mark challenge as verified (single-use) and store the linking key
            challenges.put(k1, new AuthChallenge(k1, challenge.expiresAt(), key, true));
            log.log(System.Logger.Level.DEBUG, "LNURL-auth callback verified for k1: {0}...", truncate(k1));
            return true;

        } catch (IllegalArgumentException e) {
            log.log(System.Logger.Level.ERROR, "Invalid hex encoding in LNURL-auth callback: {0}", e.getMessage());
            return false;
        } catch (Exception e) {
            log.log(System.Logger.Level.ERROR, "Signature verification error for k1: {0}...: {1}", truncate(k1), e.getMessage());
            return false;
        }
    }

    /** Returns the first 8 characters of a k1 for safe log output (avoids leaking full auth tokens). */
    private static String truncate(String k1) {
        return (k1 != null && k1.length() > 8) ? k1.substring(0, 8) : k1;
    }

    /**
     * Verify a secp256k1 ECDSA signature.
     *
     * @param message   the message that was signed (k1 challenge bytes)
     * @param signature the DER-encoded ECDSA signature bytes
     * @param publicKey the compressed secp256k1 public key bytes (33 bytes)
     * @return true if the signature is valid
     */
    private boolean verifySecp256k1Signature(byte[] message, byte[] signature, byte[] publicKey) {
        try {
            // Decompress the public key if it's in compressed format (33 bytes)
            PublicKey pubKey = decompressPublicKey(publicKey);

            // LNURL-auth: wallets sign k1 directly as the 32-byte hash (no pre-hashing).
            // k1 is already 32 random bytes -- wallets pass it as the raw message hash to secp256k1.
            // Use NONEwithECDSA so we don't SHA256 the k1 again before verifying.
            Signature ecdsaVerify = Signature.getInstance("NONEwithECDSA", "BC");
            ecdsaVerify.initVerify(pubKey);
            ecdsaVerify.update(message);

            return ecdsaVerify.verify(signature);

        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException e) {
            log.log(System.Logger.Level.ERROR, "Secp256k1 signature verification failed: {0}", e.getMessage());
            return false;
        }
    }

    /**
     * Decompress a secp256k1 compressed public key (33 bytes) to a PublicKey object.
     * Compressed format: 0x02/0x03 + 32-byte X coordinate
     *
     * @param compressedKey the 33-byte compressed public key
     * @return the PublicKey object
     */
    private PublicKey decompressPublicKey(byte[] compressedKey) {
        try {
            // Get the secp256k1 curve parameters from Bouncy Castle
            ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");

            // Decode the compressed point on the secp256k1 curve
            ECPoint point = spec.getCurve().decodePoint(compressedKey);

            // Create a public key spec from the point
            ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, spec);

            // Generate the public key using BC's KeyFactory
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            return keyFactory.generatePublic(pubKeySpec);

        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to decompress secp256k1 public key: " + e.getMessage(), e);
        }
    }

    /**
     * Check if a challenge has been authenticated (wallet responded).
     *
     * @param k1 the challenge value
     * @return the linking key if authenticated, null otherwise
     */
    public String getAuthenticatedKey(String k1) {
        AuthChallenge challenge = challenges.get(k1);
        if (challenge == null || Instant.now().isAfter(challenge.expiresAt())) {
            if (challenge != null) {
                challenges.remove(k1);
            }
            return null;
        }
        return challenge.linkingKey();
    }

    /**
     * Consume the challenge (remove after JWT is issued).
     *
     * @param k1 the challenge value to remove
     */
    public void consumeChallenge(String k1) {
        challenges.remove(k1);
    }

    /**
     * Check if a k1 challenge exists and has not expired.
     * Used by the discovery step to validate k1 before echoing it.
     *
     * @param k1 the challenge value
     * @return true if the challenge exists and is not expired
     */
    public boolean isValidChallenge(String k1) {
        AuthChallenge challenge = challenges.get(k1);
        if (challenge == null) {
            return false;
        }
        if (Instant.now().isAfter(challenge.expiresAt())) {
            challenges.remove(k1);
            return false;
        }
        return true;
    }

    /**
     * Atomically consume an authenticated challenge and return its linking key.
     * Thread-safe: only one caller can successfully consume a given k1.
     * Returns null if challenge doesn't exist, is expired, or is not yet authenticated.
     *
     * @param k1 the challenge value
     * @return the linking key if the challenge was successfully consumed, null otherwise
     */
    public String consumeAndGetKey(String k1) {
        var result = new AtomicReference<String>();
        challenges.computeIfPresent(k1, (key, challenge) -> {
            if (Instant.now().isAfter(challenge.expiresAt())) {
                return null; // remove expired entry; result stays null
            }
            if (challenge.linkingKey() != null) {
                result.set(challenge.linkingKey());
                return null; // atomically remove the consumed challenge
            }
            return challenge; // not yet authenticated -- keep entry, result stays null
        });
        return result.get();
    }

    /**
     * Remove expired challenges to prevent memory accumulation.
     * Call this periodically (e.g. every 60 seconds). When using the Spring Boot starter,
     * this is automatically scheduled via {@code @Scheduled(fixedDelay = 60_000)}.
     */
    public void cleanupExpiredChallenges() {
        var now = Instant.now();
        challenges.entrySet().removeIf(e -> now.isAfter(e.getValue().expiresAt()));
        log.log(System.Logger.Level.DEBUG, "Cleaned up expired LNURL-auth challenges");
    }
}
