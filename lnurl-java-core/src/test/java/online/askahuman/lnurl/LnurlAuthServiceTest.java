package online.askahuman.lnurl;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LnurlAuthServiceTest {

    private LnurlAuthService lnurlAuthService;
    private KeyPair testKeyPair;
    private String testPublicKeyHex;

    static {
        // Register Bouncy Castle for tests
        Security.addProvider(new BouncyCastleProvider());
    }

    @BeforeEach
    void setUp() throws Exception {
        lnurlAuthService = new LnurlAuthService(300); // 300 seconds expiry

        // Generate a test secp256k1 keypair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        keyGen.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());
        testKeyPair = keyGen.generateKeyPair();

        // Extract compressed public key (33 bytes) using BC's ECPoint
        ECPublicKey ecPublicKey = (ECPublicKey) testKeyPair.getPublic();
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");

        // Convert to BC's ECPoint and get compressed encoding
        ECPoint point = spec.getCurve().createPoint(
            ecPublicKey.getW().getAffineX(),
            ecPublicKey.getW().getAffineY()
        );
        byte[] compressedKey = point.getEncoded(true); // true = compressed format

        testPublicKeyHex = HexFormat.of().formatHex(compressedKey);
    }

    /**
     * Helper method to sign a k1 challenge with the test private key
     */
    private String signChallenge(String k1Hex) throws Exception {
        byte[] k1Bytes = HexFormat.of().parseHex(k1Hex);

        // Must match production: wallets sign k1 as the raw hash (NONEwithECDSA, no pre-hashing)
        Signature signature = Signature.getInstance("NONEwithECDSA", "BC");
        signature.initSign(testKeyPair.getPrivate());
        signature.update(k1Bytes);

        byte[] sigBytes = signature.sign();
        return HexFormat.of().formatHex(sigBytes);
    }

    // -------------------------------------------------------------------------
    // generateChallenge
    // -------------------------------------------------------------------------

    @Test
    void generateChallengeReturnsNonNullK1() {
        // When
        String k1 = lnurlAuthService.generateChallenge();

        // Then
        assertNotNull(k1);
        assertFalse(k1.isEmpty());
        // k1 should be 64 hex chars (32 bytes)
        assertEquals(64, k1.length());
    }

    @Test
    void generateChallengeShouldBeUnique() {
        // When
        String k1a = lnurlAuthService.generateChallenge();
        String k1b = lnurlAuthService.generateChallenge();

        // Then
        assertNotNull(k1a);
        assertNotNull(k1b);
        assertFalse(k1a.equals(k1b), "Each k1 challenge should be unique");
    }

    // -------------------------------------------------------------------------
    // verifyCallback — happy path
    // -------------------------------------------------------------------------

    @Test
    void verifyCallbackSuccess() throws Exception {
        // Given
        String k1 = lnurlAuthService.generateChallenge();
        String validSig = signChallenge(k1);

        // When
        boolean result = lnurlAuthService.verifyCallback(k1, validSig, testPublicKeyHex);

        // Then
        assertTrue(result, "Callback verification should succeed with valid sig and key");
    }

    // -------------------------------------------------------------------------
    // verifyCallback — input validation failures
    // -------------------------------------------------------------------------

    @Test
    void verifyCallbackFailsWithInvalidSignature() throws Exception {
        // Given
        String k1 = lnurlAuthService.generateChallenge();
        String validSig = signChallenge(k1);

        // Tamper with the signature (flip a bit)
        byte[] sigBytes = HexFormat.of().parseHex(validSig);
        sigBytes[0] ^= 0x01; // flip one bit
        String tamperedSig = HexFormat.of().formatHex(sigBytes);

        // When
        boolean result = lnurlAuthService.verifyCallback(k1, tamperedSig, testPublicKeyHex);

        // Then
        assertFalse(result, "Callback verification should fail with tampered signature");
    }

    @Test
    void verifyCallbackFailsWithWrongPublicKey() throws Exception {
        // Given
        String k1 = lnurlAuthService.generateChallenge();
        String validSig = signChallenge(k1);

        // Use a different public key
        String wrongKey = "03aabbccddee11223344556677889900aabbccddee11223344556677889900aabb";

        // When
        boolean result = lnurlAuthService.verifyCallback(k1, validSig, wrongKey);

        // Then
        assertFalse(result, "Callback verification should fail with wrong public key");
    }

    @Test
    void verifyCallbackFailsWithUnknownK1() {
        // When
        boolean result = lnurlAuthService.verifyCallback("unknown_k1_value_that_doesnt_exist_12345678901234567890123456789012", "304402207f6a7d8b", testPublicKeyHex);

        // Then
        assertFalse(result);
    }

    @Test
    void verifyCallbackFailsWithEmptySig() {
        // Given
        String k1 = lnurlAuthService.generateChallenge();

        // When
        boolean result = lnurlAuthService.verifyCallback(k1, "", testPublicKeyHex);

        // Then
        assertFalse(result);
    }

    @Test
    void verifyCallbackFailsWithNullSig() {
        // Given
        String k1 = lnurlAuthService.generateChallenge();

        // When
        boolean result = lnurlAuthService.verifyCallback(k1, null, testPublicKeyHex);

        // Then
        assertFalse(result, "Should return false for null sig");
    }

    @Test
    void verifyCallbackFailsWithNullKey() throws Exception {
        // Given
        String k1 = lnurlAuthService.generateChallenge();
        String validSig = signChallenge(k1);

        // When
        boolean result = lnurlAuthService.verifyCallback(k1, validSig, null);

        // Then
        assertFalse(result);
    }

    @Test
    void verifyCallbackFailsWithShortKey() throws Exception {
        // Given
        String k1 = lnurlAuthService.generateChallenge();
        String validSig = signChallenge(k1);

        // When - key is too short (not 66 hex chars for compressed key)
        boolean result = lnurlAuthService.verifyCallback(k1, validSig, "02aabb");

        // Then
        assertFalse(result);
    }

    /**
     * Sig that passes the length check (140 chars) but contains non-hex characters.
     * This exercises the HexFormat.parseHex exception path in verifyCallback.
     */
    @Test
    void verifyCallbackFailsWithNonHexSig() {
        // Given
        String k1 = lnurlAuthService.generateChallenge();
        // 140 chars that pass the length check but contain invalid hex characters ('z' is not hex)
        String nonHexSig = "z".repeat(140);

        // When
        boolean result = lnurlAuthService.verifyCallback(k1, nonHexSig, testPublicKeyHex);

        // Then
        assertFalse(result, "Should return false for non-hex sig");
    }

    /**
     * Sig that is valid hex at the correct length but is NOT a valid DER-encoded signature.
     * This exercises the SignatureException path inside verifySecp256k1Signature.
     */
    @Test
    void verifyCallbackFailsWithNonDerSig() {
        // Given
        String k1 = lnurlAuthService.generateChallenge();
        // 140 hex chars — valid length, valid hex, but not a DER-encoded ECDSA signature
        String validHexNotDer = "aa".repeat(70);

        // When
        boolean result = lnurlAuthService.verifyCallback(k1, validHexNotDer, testPublicKeyHex);

        // Then
        assertFalse(result, "Should return false for hex-valid but non-DER signature");
    }

    /**
     * Key is 66 hex chars (correct length) but starts with 0x04 (uncompressed prefix).
     * This exercises the decompressPublicKey failure path: EC point decoding will reject
     * a 33-byte buffer that begins with 0x04 (an uncompressed point requires 65 bytes).
     */
    @Test
    void verifyCallbackFailsWithInvalidKeyPrefix() throws Exception {
        // Given
        String k1 = lnurlAuthService.generateChallenge();
        String validSig = signChallenge(k1);
        // 66-char hex key with invalid compressed-point prefix (0x04 = uncompressed)
        String invalidPrefixKey = "04" + "aabbccddee11223344556677889900aabbccddee11223344556677889900aa";

        // When
        boolean result = lnurlAuthService.verifyCallback(k1, validSig, invalidPrefixKey);

        // Then
        assertFalse(result, "Should return false for key with invalid compressed-point prefix");
    }

    /**
     * Key is 66 characters long but contains non-hex characters ('z').
     * This exercises the HexFormat.parseHex exception for the key param.
     */
    @Test
    void verifyCallbackFailsWithNonHexKey() throws Exception {
        // Given
        String k1 = lnurlAuthService.generateChallenge();
        String validSig = signChallenge(k1);
        // 66 chars but not valid hex — 'z' is not a hex digit
        String nonHexKey = "02" + "zz".repeat(32);

        // When
        boolean result = lnurlAuthService.verifyCallback(k1, validSig, nonHexKey);

        // Then
        assertFalse(result, "Should return false for non-hex key (even if correct length)");
    }

    // -------------------------------------------------------------------------
    // verifyCallback — expiry
    // -------------------------------------------------------------------------

    @Test
    void verifyCallbackExpired() throws Exception {
        // Given - create a service with 0-second expiry
        LnurlAuthService expiredService = new LnurlAuthService(0);
        String k1 = expiredService.generateChallenge();
        String validSig = signChallenge(k1);

        // Wait a moment to ensure expiry
        Thread.sleep(10);

        // When - challenge is already expired
        boolean result = expiredService.verifyCallback(k1, validSig, testPublicKeyHex);

        // Then
        assertFalse(result, "Expired challenges should fail verification");
    }

    // -------------------------------------------------------------------------
    // verifyCallback — security invariant
    // -------------------------------------------------------------------------

    /**
     * A failed verifyCallback must NOT mark the challenge as authenticated.
     * Prevents a race condition where a partial authentication could be exploited.
     */
    @Test
    void failedVerifyCallbackDoesNotAuthenticateChallenge() throws Exception {
        // Given
        String k1 = lnurlAuthService.generateChallenge();
        String invalidSig = "aa".repeat(70); // valid hex length, invalid DER

        // When — verification fails
        lnurlAuthService.verifyCallback(k1, invalidSig, testPublicKeyHex);

        // Then — challenge must NOT be marked as authenticated
        assertNull(lnurlAuthService.getAuthenticatedKey(k1),
                "Failed verification should not authenticate the challenge");
    }

    // -------------------------------------------------------------------------
    // getAuthenticatedKey
    // -------------------------------------------------------------------------

    @Test
    void getAuthenticatedKeyAfterVerify() throws Exception {
        // Given
        String k1 = lnurlAuthService.generateChallenge();
        String validSig = signChallenge(k1);

        // Before callback - should be null (not yet authenticated)
        assertNull(lnurlAuthService.getAuthenticatedKey(k1));

        // When
        lnurlAuthService.verifyCallback(k1, validSig, testPublicKeyHex);

        // Then
        String authenticatedKey = lnurlAuthService.getAuthenticatedKey(k1);
        assertEquals(testPublicKeyHex, authenticatedKey);
    }

    @Test
    void getAuthenticatedKeyReturnsNullForUnknownK1() {
        assertNull(lnurlAuthService.getAuthenticatedKey("nonexistent_k1"));
    }

    @Test
    void getAuthenticatedKeyReturnsNullForExpiredChallenge() throws Exception {
        // Given - a service with 0-second expiry
        LnurlAuthService expiredService = new LnurlAuthService(0);
        String k1 = expiredService.generateChallenge();
        Thread.sleep(10);

        // When / Then
        assertNull(expiredService.getAuthenticatedKey(k1),
                "Should return null for an expired challenge");
    }

    // -------------------------------------------------------------------------
    // consumeChallenge
    // -------------------------------------------------------------------------

    @Test
    void consumeChallengeRemovesChallenge() throws Exception {
        // Given
        String k1 = lnurlAuthService.generateChallenge();
        String validSig = signChallenge(k1);
        lnurlAuthService.verifyCallback(k1, validSig, testPublicKeyHex);
        assertNotNull(lnurlAuthService.getAuthenticatedKey(k1));

        // When
        lnurlAuthService.consumeChallenge(k1);

        // Then
        assertNull(lnurlAuthService.getAuthenticatedKey(k1));
    }

    @Test
    void consumeChallengeWithUnknownK1DoesNotThrow() {
        assertDoesNotThrow(
                () -> lnurlAuthService.consumeChallenge("nonexistent_k1_that_was_never_generated"),
                "consumeChallenge must not throw for an unknown k1");
    }

    // -------------------------------------------------------------------------
    // isValidChallenge
    // -------------------------------------------------------------------------

    @Test
    void isValidChallengeReturnsTrueForValidChallenge() {
        String k1 = lnurlAuthService.generateChallenge();
        assertTrue(lnurlAuthService.isValidChallenge(k1));
    }

    @Test
    void isValidChallengeReturnsFalseForUnknownK1() {
        assertFalse(lnurlAuthService.isValidChallenge("unknown_k1_not_generated_by_this_service"));
    }

    @Test
    void isValidChallengeReturnsFalseForExpiredChallenge() throws Exception {
        // Given - a service with 0-second expiry
        LnurlAuthService expiredService = new LnurlAuthService(0);
        String k1 = expiredService.generateChallenge();
        Thread.sleep(10);

        // When / Then
        assertFalse(expiredService.isValidChallenge(k1),
                "Should return false for an expired challenge");
    }

    // -------------------------------------------------------------------------
    // consumeAndGetKey
    // -------------------------------------------------------------------------

    @Test
    void consumeAndGetKeyReturnsKeyAfterAuthentication() throws Exception {
        // Given
        String k1 = lnurlAuthService.generateChallenge();
        String validSig = signChallenge(k1);
        lnurlAuthService.verifyCallback(k1, validSig, testPublicKeyHex);

        // When — first call consumes the challenge and returns the key
        String key = lnurlAuthService.consumeAndGetKey(k1);
        assertEquals(testPublicKeyHex, key);

        // Second call must return null (challenge was consumed)
        assertNull(lnurlAuthService.consumeAndGetKey(k1),
                "Second consumeAndGetKey call should return null — challenge already consumed");
    }

    @Test
    void consumeAndGetKeyReturnsNullForUnauthenticatedChallenge() {
        // Given — challenge exists but wallet has not yet responded
        String k1 = lnurlAuthService.generateChallenge();

        // When
        assertNull(lnurlAuthService.consumeAndGetKey(k1),
                "consumeAndGetKey should return null for a challenge that is not yet authenticated");

        // Challenge must still be present (not consumed on a null return)
        assertTrue(lnurlAuthService.isValidChallenge(k1),
                "Challenge should remain valid after a null consumeAndGetKey");
    }

    @Test
    void consumeAndGetKeyReturnsNullForUnknownK1() {
        assertNull(lnurlAuthService.consumeAndGetKey("k1_that_was_never_generated"),
                "consumeAndGetKey should return null for an unknown k1");
    }

    // -------------------------------------------------------------------------
    // cleanupExpiredChallenges
    // -------------------------------------------------------------------------

    @Test
    void cleanupExpiredChallengesRemovesExpiredEntries() throws Exception {
        // Given — a service with 0-second expiry
        LnurlAuthService shortLivedService = new LnurlAuthService(0);
        String k1 = shortLivedService.generateChallenge();
        Thread.sleep(10); // let it expire

        // When
        shortLivedService.cleanupExpiredChallenges();

        // Then — the expired challenge is gone
        assertFalse(shortLivedService.isValidChallenge(k1),
                "cleanupExpiredChallenges should remove the expired challenge");
    }

    @Test
    void cleanupExpiredChallengesDoesNotRemoveActiveChallenges() {
        // Given — normal 300-second expiry
        String k1 = lnurlAuthService.generateChallenge();

        // When
        lnurlAuthService.cleanupExpiredChallenges();

        // Then — active challenge must still be there
        assertTrue(lnurlAuthService.isValidChallenge(k1),
                "cleanupExpiredChallenges must not remove active (non-expired) challenges");
    }
}
