package online.askahuman.lnurl;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Bech32 encoding utility for LNURL per LUD-01 specification.
 *
 * <p>LNURL encoding: take URL bytes, convert from 8-bit to 5-bit groups,
 * prepend HRP "lnurl" with separator "1", append 6-character bech32 checksum.
 * Result is returned uppercase for efficient QR alphanumeric encoding.</p>
 */
public final class Bech32Utils {

    private static final System.Logger log = System.getLogger(Bech32Utils.class.getName());
    private static final String CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private static final int[] GENERATOR = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    private static final String HRP = "lnurl";
    private static final int[] CHARSET_REV = buildCharsetRev();

    private static int[] buildCharsetRev() {
        int[] rev = new int[128];
        Arrays.fill(rev, -1);
        for (int i = 0; i < CHARSET.length(); i++) {
            rev[CHARSET.charAt(i)] = i;
        }
        return rev;
    }

    private Bech32Utils() {}

    /**
     * Bech32-encode a URL as an LNURL per LUD-01.
     * Returns uppercase string (e.g. "LNURL1DP68GURN8...") suitable for QR display.
     *
     * @param url the raw HTTPS URL to encode
     * @return bech32-encoded LNURL string (uppercase)
     */
    public static String encodeLnurl(String url) {
        if (url == null || url.isEmpty()) {
            throw new IllegalArgumentException("URL must not be null or empty");
        }
        if (url.length() > 2000) {
            throw new IllegalArgumentException("URL length exceeds maximum of 2000 characters");
        }
        if (!url.startsWith("https://") && !url.startsWith("http://")) {
            throw new IllegalArgumentException("LNURL URL must use https:// or http:// scheme");
        }
        if (url.startsWith("http://")) {
            log.log(System.Logger.Level.WARNING,
                    "Encoding non-HTTPS LNURL: HTTP URLs should only be used with .onion addresses");
        }
        byte[] urlBytes = url.getBytes(StandardCharsets.UTF_8);
        byte[] data5bit = convertBits(urlBytes, 8, 5, true);

        byte[] checksumInput = buildChecksumInput(HRP, data5bit);
        long polymod = polymod(checksumInput) ^ 1L;

        StringBuilder sb = new StringBuilder(HRP).append("1");
        for (byte b : data5bit) {
            sb.append(CHARSET.charAt(b & 0x1f));
        }
        for (int i = 0; i < 6; i++) {
            sb.append(CHARSET.charAt((int) ((polymod >> (5 * (5 - i))) & 0x1f)));
        }

        return sb.toString().toUpperCase();
    }

    /**
     * Decode a Bech32-encoded LNURL back to its original URL per LUD-01.
     * Accepts both uppercase and lowercase input.
     *
     * @param lnurl the bech32-encoded LNURL string (e.g. "LNURL1DP68GURN8...")
     * @return the decoded URL string (starts with {@code https://} or {@code http://})
     * @throws IllegalArgumentException if the input is null, empty, does not start with
     *                                  {@code lnurl1}, contains an invalid character,
     *                                  has a bad checksum, or decodes to a non-HTTP URL
     */
    public static String decodeLnurl(String lnurl) {
        if (lnurl == null || lnurl.isEmpty()) {
            throw new IllegalArgumentException("LNURL must not be null or empty");
        }
        String lower = lnurl.toLowerCase();
        if (!lower.startsWith("lnurl1")) {
            throw new IllegalArgumentException(
                    "Input is not a valid LNURL: must start with 'lnurl1'");
        }

        // Strip the "lnurl1" prefix (HRP "lnurl" + separator "1")
        String dataChars = lower.substring(6);
        if (dataChars.length() < 6) {
            throw new IllegalArgumentException(
                    "LNURL data is too short (no payload before checksum)");
        }

        // Map each character to its 5-bit value
        byte[] all5bit = new byte[dataChars.length()];
        for (int i = 0; i < dataChars.length(); i++) {
            char c = dataChars.charAt(i);
            if (c >= 128) {
                throw new IllegalArgumentException(
                        "LNURL contains non-ASCII character: '" + c + "'");
            }
            int val = CHARSET_REV[c];
            if (val == -1) {
                throw new IllegalArgumentException(
                        "LNURL contains invalid bech32 character: '" + c + "'");
            }
            all5bit[i] = (byte) val;
        }

        // Verify checksum: polymod(hrp-expand + all5bit) must equal 1
        byte[] expanded = hrpExpand(HRP);
        byte[] checksumInput = new byte[expanded.length + all5bit.length];
        System.arraycopy(expanded, 0, checksumInput, 0, expanded.length);
        System.arraycopy(all5bit, 0, checksumInput, expanded.length, all5bit.length);
        if (polymod(checksumInput) != 1L) {
            throw new IllegalArgumentException(
                    "LNURL checksum verification failed (corrupted or tampered input)");
        }

        // Strip the last 6 checksum characters to get the data payload
        byte[] data5bit = Arrays.copyOf(all5bit, all5bit.length - 6);

        // Convert from 5-bit groups back to 8-bit bytes
        byte[] urlBytes = convertBits(data5bit, 5, 8, false);

        String url = new String(urlBytes, StandardCharsets.UTF_8);
        if (!url.startsWith("https://") && !url.startsWith("http://")) {
            throw new IllegalArgumentException(
                    "Decoded LNURL does not contain a valid HTTP(S) URL: " + url);
        }

        return url;
    }

    private static long polymod(byte[] values) {
        long chk = 1L;
        for (byte b : values) {
            int c0 = (int) (chk >> 25);
            chk = ((chk & 0x1ffffffL) << 5) ^ (b & 0xff);
            for (int i = 0; i < 5; i++) {
                if (((c0 >> i) & 1) != 0) {
                    chk ^= GENERATOR[i];
                }
            }
        }
        return chk;
    }

    private static byte[] buildChecksumInput(String hrp, byte[] data) {
        byte[] expanded = hrpExpand(hrp);
        byte[] combined = new byte[expanded.length + data.length + 6];
        System.arraycopy(expanded, 0, combined, 0, expanded.length);
        System.arraycopy(data, 0, combined, expanded.length, data.length);
        return combined;
    }

    private static byte[] hrpExpand(String hrp) {
        byte[] result = new byte[hrp.length() * 2 + 1];
        for (int i = 0; i < hrp.length(); i++) {
            result[i] = (byte) (hrp.charAt(i) >> 5);
            result[i + hrp.length() + 1] = (byte) (hrp.charAt(i) & 0x1f);
        }
        result[hrp.length()] = 0;
        return result;
    }

    private static byte[] convertBits(byte[] data, int fromBits, int toBits, boolean pad) {
        int acc = 0, bits = 0;
        int maxv = (1 << toBits) - 1;
        int outputSize = (data.length * fromBits + (pad ? toBits - 1 : 0)) / toBits;
        byte[] result = new byte[outputSize];
        int idx = 0;

        for (byte b : data) {
            acc = (acc << fromBits) | (b & 0xff);
            bits += fromBits;
            while (bits >= toBits) {
                bits -= toBits;
                result[idx++] = (byte) ((acc >> bits) & maxv);
            }
        }

        if (pad && bits > 0) {
            result[idx] = (byte) ((acc << (toBits - bits)) & maxv);
        }

        return result;
    }
}
