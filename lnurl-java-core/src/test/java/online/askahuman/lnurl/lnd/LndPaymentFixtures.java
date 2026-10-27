package online.askahuman.lnurl.lnd;

import java.security.MessageDigest;
import java.util.HexFormat;

/** Shared helpers for building consistent LND payment responses in tests. */
final class LndPaymentFixtures {

    private LndPaymentFixtures() {
    }

    /** SHA-256 of the hex-encoded bytes, as hex: the payment hash for a preimage. */
    static String sha256Hex(String preimageHex) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(HexFormat.of().parseHex(preimageHex)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String succeededLine(String hash, String preimage) {
        return "{\"result\":{\"payment_hash\":\"" + hash + "\",\"payment_preimage\":\"" + preimage
                + "\",\"status\":\"SUCCEEDED\"}}";
    }

    static String statusLine(String hash, String status) {
        return "{\"result\":{\"payment_hash\":\"" + hash + "\",\"status\":\"" + status + "\"}}";
    }
}
