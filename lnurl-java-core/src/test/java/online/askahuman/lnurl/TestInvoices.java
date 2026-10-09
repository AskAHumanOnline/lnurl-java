package online.askahuman.lnurl;

import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;

/**
 * Builds structurally valid, bech32-checksum-valid BOLT11 invoices for tests. The signature is
 * 104 zero words: {@link Bolt11Invoice} checks that it is present and sized correctly, not the
 * ECDSA signature itself.
 *
 * <p>The bech32 encoder below is deliberately a separate, minimal reimplementation of BIP-173
 * rather than a call into the production code, so a passing parser test does not just prove the
 * parser agrees with itself.</p>
 */
final class TestInvoices {

    /** Fixed payment hash used by default (the BOLT11 spec example hash). */
    static final String DEFAULT_PAYMENT_HASH =
            "0001020304050607080900010203040506070809000102030405060708090102";

    private static final String CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private static final int[] GENERATOR = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    private static final int SIGNATURE_WORDS = 104;

    private TestInvoices() {}

    static Builder builder() {
        return new Builder();
    }

    /** Mainnet invoice for exactly {@code sats}, created now, default 1 h expiry. */
    static String mainnetForSats(long sats) {
        return builder().hrp("lnbc" + (sats * 10) + "n").build();
    }

    /** {@code {"pr":"<invoice>"}}, the body a provider's callback returns. */
    static String callbackBody(String invoice) {
        return "{\"pr\":\"" + invoice + "\"}";
    }

    static final class Builder {
        private String hrp = "lnbc";
        private long timestamp = System.currentTimeMillis() / 1000;
        private Long expirySeconds;
        private String paymentHash = DEFAULT_PAYMENT_HASH;
        private int expiryTags = 1;
        private final List<int[]> extraTags = new ArrayList<>();
        private boolean paymentHashTag = true;
        private int signatureWords = SIGNATURE_WORDS;

        /** Full human-readable part, e.g. {@code lnbc2500u}, {@code lnbcrt}, {@code lnbc}. */
        Builder hrp(String value) {
            this.hrp = value;
            return this;
        }

        Builder timestamp(long epochSeconds) {
            this.timestamp = epochSeconds;
            return this;
        }

        /** Adds an {@code x} (expiry) tag; omitted by default, so the BOLT11 default of 3600 s applies. */
        Builder expirySeconds(long value) {
            this.expirySeconds = value;
            return this;
        }

        /** Emits the expiry tag this many times (only meaningful after {@link #expirySeconds}). */
        Builder expiryTags(int count) {
            this.expiryTags = count;
            return this;
        }

        Builder paymentHash(String hex) {
            this.paymentHash = hex;
            return this;
        }

        /** Appends a raw tag: type, then its data words. */
        Builder rawTag(int type, int... dataWords) {
            var tag = new int[dataWords.length + 1];
            tag[0] = type;
            System.arraycopy(dataWords, 0, tag, 1, dataWords.length);
            extraTags.add(tag);
            return this;
        }

        /**
         * Appends a tag whose header declares {@code declaredLength} words regardless of how many
         * data words follow, to build a tag that claims to run past the end of its region.
         */
        Builder rawTagDeclaringLength(int type, int declaredLength, int... dataWords) {
            var tag = new int[dataWords.length + 2];
            tag[0] = -1 - type; // negative marker: second slot carries the declared length
            tag[1] = declaredLength;
            System.arraycopy(dataWords, 0, tag, 2, dataWords.length);
            extraTags.add(tag);
            return this;
        }

        /** Omits the payment-hash tag, so only the tags added explicitly are present. */
        Builder withoutPaymentHash() {
            this.paymentHashTag = false;
            return this;
        }

        /** Number of signature words (104 is valid); lets tests build a truncated invoice. */
        Builder signatureWords(int count) {
            this.signatureWords = count;
            return this;
        }

        String build() {
            var data = new ArrayList<Integer>();
            for (int shift = 30; shift >= 0; shift -= 5) {
                data.add((int) ((timestamp >> shift) & 0x1f));
            }
            if (paymentHashTag) {
                addTag(data, 1, bytesToWords(HexFormat.of().parseHex(paymentHash)));
            }
            if (expirySeconds != null) {
                for (int n = 0; n < expiryTags; n++) {
                    addTag(data, 6, numberToWords(expirySeconds));
                }
            }
            for (var tag : extraTags) {
                if (tag[0] < 0) {
                    data.add(-1 - tag[0]);
                    data.add(tag[1] >> 5);
                    data.add(tag[1] & 0x1f);
                    for (int n = 2; n < tag.length; n++) {
                        data.add(tag[n]);
                    }
                    continue;
                }
                var words = new int[tag.length - 1];
                System.arraycopy(tag, 1, words, 0, words.length);
                addTag(data, tag[0], words);
            }
            for (int n = 0; n < signatureWords; n++) {
                data.add(0);
            }
            return encode(hrp, data);
        }
    }

    private static void addTag(List<Integer> data, int type, int[] words) {
        data.add(type);
        data.add(words.length >> 5);
        data.add(words.length & 0x1f);
        for (int w : words) {
            data.add(w);
        }
    }

    private static int[] numberToWords(long value) {
        var words = new ArrayList<Integer>();
        long rest = value;
        do {
            words.add(0, (int) (rest & 0x1f));
            rest >>= 5;
        } while (rest > 0);
        return words.stream().mapToInt(Integer::intValue).toArray();
    }

    private static int[] bytesToWords(byte[] bytes) {
        var out = new ArrayList<Integer>();
        int acc = 0;
        int bits = 0;
        for (byte b : bytes) {
            acc = (acc << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                out.add((acc >> bits) & 0x1f);
            }
        }
        if (bits > 0) {
            out.add((acc << (5 - bits)) & 0x1f);
        }
        return out.stream().mapToInt(Integer::intValue).toArray();
    }

    private static String encode(String hrp, List<Integer> data) {
        var lowerHrp = hrp.toLowerCase(Locale.ROOT);
        var values = new ArrayList<Integer>();
        for (char c : lowerHrp.toCharArray()) {
            values.add(c >> 5);
        }
        values.add(0);
        for (char c : lowerHrp.toCharArray()) {
            values.add(c & 0x1f);
        }
        values.addAll(data);
        for (int n = 0; n < 6; n++) {
            values.add(0);
        }
        int mod = polymod(values) ^ 1;

        var sb = new StringBuilder(lowerHrp).append('1');
        for (int w : data) {
            sb.append(CHARSET.charAt(w));
        }
        for (int n = 0; n < 6; n++) {
            sb.append(CHARSET.charAt((mod >> (5 * (5 - n))) & 0x1f));
        }
        return sb.toString();
    }

    private static int polymod(List<Integer> values) {
        int chk = 1;
        for (int v : values) {
            int top = chk >>> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ v;
            for (int i = 0; i < 5; i++) {
                if (((top >> i) & 1) != 0) {
                    chk ^= GENERATOR[i];
                }
            }
        }
        return chk;
    }
}
