package online.askahuman.lnurl;

import online.askahuman.lnurl.LnurlInvoiceRejectedException.Reason;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * The few BOLT11 fields {@link LnurlPayClient} needs to check a provider's invoice: the amount
 * (exact millisatoshis), the creation time and the expiry.
 *
 * <p>This is a deliberately small reader, not a full BOLT11 implementation. It verifies the
 * bech32 checksum and the overall structure, but not the invoice signature: it cannot tell who
 * issued the invoice. The checksum is an integrity check, not authentication. What makes the
 * amount check meaningful is that the caller then pays this exact string with a node that
 * verifies the signature and reads the same signed human-readable part, so an invoice that
 * passes here cannot cost more than it says.</p>
 *
 * <p>Neither the network nor a minimum remaining validity is checked here; those are policy for
 * the application, which knows its chain and how long a payment may take.</p>
 */
final class Bolt11Invoice {

    /** Longest invoice string accepted; real invoices are a few hundred characters. */
    private static final int MAX_INVOICE_CHARS = 10_000;

    private static final int CHECKSUM_WORDS = 6;
    private static final int TIMESTAMP_WORDS = 7;
    /** 64-byte signature plus recovery id = 65 bytes = 520 bits = 104 five-bit words. */
    private static final int SIGNATURE_WORDS = 104;
    private static final int TAG_EXPIRY = 6;
    /** Longest expiry value accepted, in words (35 bits is more than a millennium of seconds). */
    private static final int MAX_EXPIRY_WORDS = 7;
    private static final long DEFAULT_EXPIRY_SECONDS = 3600;

    private static final long MSAT_PER_BTC = 100_000_000_000L;
    /** 21 million BTC in millisatoshis: no valid invoice can exceed it. */
    private static final long MAX_MSAT = 21_000_000L * MSAT_PER_BTC;

    /**
     * Mainnet, testnet, signet, regtest and simnet (the last is lnd/btcd's, not in the BOLT11
     * table). Longest prefix first, so "lnbcrt" is not read as "lnbc" followed by amount text "rt".
     */
    private static final List<String> NETWORK_PREFIXES =
            List.of("lnbcrt", "lntbs", "lnbc", "lntb", "lnsb");
    /** At most 18 digits so the number always fits a {@code long}; no leading zeros. */
    private static final Pattern AMOUNT = Pattern.compile("([1-9][0-9]{0,17})([munp])?");

    private final Long amountMsat;
    private final Instant createdAt;
    private final long expirySeconds;

    private Bolt11Invoice(Long amountMsat, Instant createdAt, long expirySeconds) {
        this.amountMsat = amountMsat;
        this.createdAt = createdAt;
        this.expirySeconds = expirySeconds;
    }

    /** @return the invoiced amount in millisatoshis, or {@code null} for an amountless invoice */
    Long amountMsat() {
        return amountMsat;
    }

    Instant expiresAt() {
        return createdAt.plusSeconds(expirySeconds);
    }

    /**
     * Parses and structurally validates a BOLT11 invoice.
     *
     * @throws LnurlInvoiceRejectedException with {@link Reason#MALFORMED} for anything that is not
     *                                       a well-formed, checksum-valid invoice
     */
    static Bolt11Invoice parse(String invoice) {
        if (invoice == null || invoice.isEmpty()) {
            throw malformed("invoice is empty");
        }
        if (invoice.length() > MAX_INVOICE_CHARS) {
            throw malformed("invoice is too long");
        }
        var text = normalizeCase(invoice);

        var separator = text.lastIndexOf('1');
        if (separator < 1) {
            throw malformed("no bech32 separator");
        }
        var hrp = text.substring(0, separator);
        var words = decodeWords(text, separator);
        if (!Bech32Utils.hasValidChecksum(hrp, words)) {
            throw malformed("checksum mismatch");
        }

        var payloadWords = words.length - CHECKSUM_WORDS;
        if (payloadWords < TIMESTAMP_WORDS + SIGNATURE_WORDS) {
            throw malformed("invoice is too short");
        }
        var amountMsat = parseAmountMsat(hrp);

        long timestamp = 0;
        for (int i = 0; i < TIMESTAMP_WORDS; i++) {
            timestamp = (timestamp << 5) | words[i];
        }
        var expirySeconds = parseExpiry(words, TIMESTAMP_WORDS, payloadWords - SIGNATURE_WORDS);

        return new Bolt11Invoice(amountMsat, Instant.ofEpochSecond(timestamp), expirySeconds);
    }

    /** Upper-case invoices are legal (QR codes); mixed case is not (BIP-173). */
    private static String normalizeCase(String invoice) {
        var hasLower = false;
        var hasUpper = false;
        for (int i = 0; i < invoice.length(); i++) {
            var c = invoice.charAt(i);
            if (c >= 128) {
                throw malformed("invoice contains a non-ASCII character");
            }
            hasLower |= c >= 'a' && c <= 'z';
            hasUpper |= c >= 'A' && c <= 'Z';
        }
        if (hasLower && hasUpper) {
            throw malformed("invoice mixes upper and lower case");
        }
        return invoice.toLowerCase(Locale.ROOT);
    }

    private static byte[] decodeWords(String text, int separator) {
        var data = text.substring(separator + 1);
        if (data.length() < CHECKSUM_WORDS) {
            throw malformed("invoice has no data part");
        }
        var words = new byte[data.length()];
        for (int i = 0; i < data.length(); i++) {
            var value = Bech32Utils.wordValue(data.charAt(i));
            if (value < 0) {
                throw malformed("invalid bech32 character at data index " + i);
            }
            words[i] = (byte) value;
        }
        return words;
    }

    /** @return exact millisatoshis, or {@code null} when the human-readable part has no amount */
    private static Long parseAmountMsat(String hrp) {
        var prefix = NETWORK_PREFIXES.stream().filter(hrp::startsWith).findFirst()
                .orElseThrow(() -> malformed("unknown network prefix"));
        var amountText = hrp.substring(prefix.length());
        if (amountText.isEmpty()) {
            return null;
        }
        var matcher = AMOUNT.matcher(amountText);
        if (!matcher.matches()) {
            throw malformed("invalid amount");
        }
        var number = Long.parseLong(matcher.group(1));
        var multiplier = matcher.group(2);
        long msat;
        try {
            msat = switch (multiplier == null ? "" : multiplier) {
                case "" -> Math.multiplyExact(number, MSAT_PER_BTC);
                case "m" -> Math.multiplyExact(number, MSAT_PER_BTC / 1_000);
                case "u" -> Math.multiplyExact(number, MSAT_PER_BTC / 1_000_000);
                case "n" -> Math.multiplyExact(number, MSAT_PER_BTC / 1_000_000_000);
                default -> {
                    // "p" is 0.1 msat per unit, so only multiples of 10 are whole millisatoshis.
                    if (number % 10 != 0) {
                        throw malformed("amount has sub-millisatoshi precision");
                    }
                    yield number / 10;
                }
            };
        } catch (ArithmeticException e) {
            throw malformed("amount is out of range");
        }
        if (msat > MAX_MSAT) {
            throw malformed("amount exceeds the total bitcoin supply");
        }
        return msat;
    }

    /** Walks the tagged fields in {@code [from, to)} and returns the expiry (default 3600 s). */
    private static long parseExpiry(byte[] words, int from, int to) {
        Long expiry = null;
        var i = from;
        while (i < to) {
            if (i + 3 > to) {
                throw malformed("truncated tag header");
            }
            var type = words[i];
            var length = words[i + 1] * 32 + words[i + 2];
            i += 3;
            if (i + length > to) {
                throw malformed("tag runs past the end of the data");
            }
            if (type == TAG_EXPIRY) {
                if (expiry != null) {
                    throw malformed("duplicate expiry tag");
                }
                if (length < 1 || length > MAX_EXPIRY_WORDS) {
                    throw malformed("invalid expiry length");
                }
                long value = 0;
                for (int j = 0; j < length; j++) {
                    value = (value << 5) | words[i + j];
                }
                expiry = value;
            }
            i += length;
        }
        return expiry == null ? DEFAULT_EXPIRY_SECONDS : expiry;
    }

    private static LnurlInvoiceRejectedException malformed(String detail) {
        return new LnurlInvoiceRejectedException(Reason.MALFORMED, detail);
    }
}
