package online.askahuman.lnurl;

import java.nio.charset.StandardCharsets;

/**
 * Bech32 encoding utility for LNURL per LUD-01 specification.
 *
 * <p>LNURL encoding: take URL bytes, convert from 8-bit to 5-bit groups,
 * prepend HRP "lnurl" with separator "1", append 6-character bech32 checksum.
 * Result is returned uppercase for efficient QR alphanumeric encoding.</p>
 */
public final class Bech32Utils {

    private static final String CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private static final int[] GENERATOR = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    private static final String HRP = "lnurl";

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
