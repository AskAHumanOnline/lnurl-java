package online.askahuman.lnurl;

import online.askahuman.lnurl.LnurlInvoiceRejectedException.Reason;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Bolt11Invoice Tests")
class Bolt11InvoiceTest {

    /** Timestamp used by the BOLT11 specification examples (2017-06-01T10:57:38Z). */
    private static final long SPEC_TIMESTAMP = 1_496_314_658L;

    private static Bolt11Invoice parse(String invoice) {
        return Bolt11Invoice.parse(invoice);
    }

    private static Bolt11Invoice parseHrp(String hrp) {
        return parse(TestInvoices.builder().hrp(hrp).build());
    }

    private static void assertMalformed(String invoice) {
        var e = assertThrows(LnurlInvoiceRejectedException.class, () -> parse(invoice));
        assertEquals(Reason.MALFORMED, e.getReason());
    }

    private static String replaceAt(String text, int index, char replacement) {
        return text.substring(0, index) + replacement + text.substring(index + 1);
    }

    /** Index of the first data character (the one after the bech32 separator). */
    private static int dataStart(String invoice) {
        return invoice.lastIndexOf('1') + 1;
    }

    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Amount")
    class Amount {

        @ParameterizedTest(name = "{0} = {1} msat")
        @CsvSource({
                "lnbc1,                  100000000000",
                "lnbc2,                  200000000000",
                "lnbc20m,                2000000000",
                "lnbc1m,                 100000000",
                "lnbc2500u,              250000000",
                "lnbc1u,                 100000",
                "lnbc10n,                1000",
                "lnbc1n,                 100",
                "lnbc9678785340p,        967878534",
                "lnbc10p,                1",
                "lnbc20p,                2",
                "lnbc100n,               10000",
                "lnbc999999999999999990p, 99999999999999999",
        })
        @DisplayName("every multiplier converts to the exact number of millisatoshis")
        void multipliers_convertExactly(String hrp, long expectedMsat) {
            assertEquals(expectedMsat, parseHrp(hrp).amountMsat());
        }

        @ParameterizedTest(name = "{0} is rejected")
        @ValueSource(strings = {"lnbc1p", "lnbc15p", "lnbc5p", "lnbc9678785341p", "lnbc11p"})
        @DisplayName("p amounts that are not a multiple of 10 (sub-millisatoshi) are rejected")
        void picoNotMultipleOfTen_isRejected(String hrp) {
            assertMalformed(TestInvoices.builder().hrp(hrp).build());
        }

        @ParameterizedTest(name = "{0} is rejected")
        @ValueSource(strings = {"lnbc0", "lnbc0u", "lnbc01u", "lnbc00n", "lnbc0m", "lnbc007"})
        @DisplayName("amounts with a leading zero are rejected")
        void leadingZero_isRejected(String hrp) {
            assertMalformed(TestInvoices.builder().hrp(hrp).build());
        }

        @ParameterizedTest(name = "{0} is rejected")
        @ValueSource(strings = {"lnbc100x", "lnbc100nn", "lnbcu", "lnbc-5", "lnbc1.5u", "lnbc100 n", "lnbcm5"})
        @DisplayName("amounts that are not digits followed by an optional multiplier are rejected")
        void invalidAmountText_isRejected(String hrp) {
            assertMalformed(TestInvoices.builder().hrp(hrp).build());
        }

        @ParameterizedTest(name = "{0} is rejected")
        @ValueSource(strings = {
                "lnbc999999999999999999",              // 18 digits of whole BTC: overflows a long in msat
                "lnbc999999999999999999m",
                "lnbc999999999999999999u",
                "lnbc21000001",                        // 21,000,001 BTC: fits a long but exceeds the supply
                "lnbc21000000001m",
                "lnbc21000000000001u",
                "lnbc21000000000000001n",              // the cap in its finest granularity
        })
        @DisplayName("amounts that overflow or exceed 21 million BTC are rejected")
        void overflowOrOverSupply_isRejected(String hrp) {
            assertMalformed(TestInvoices.builder().hrp(hrp).build());
        }

        @Test
        @DisplayName("exactly 21 million BTC is accepted, one nanobitcoin more is not")
        void supplyCap_boundary() {
            assertEquals(2_100_000_000_000_000_000L, parseHrp("lnbc21000000").amountMsat());
            assertEquals(2_100_000_000_000_000_000L, parseHrp("lnbc21000000000000000n").amountMsat());
            assertMalformed(TestInvoices.builder().hrp("lnbc21000000000000001n").build());
        }

        @ParameterizedTest(name = "{0} is rejected")
        @ValueSource(strings = {
                "lnbc1000000000000000000n",            // 19 digits
                "lnbc9999999999999999999",
                "lnbc12345678901234567890u",
        })
        @DisplayName("amounts with 19 or more digits are rejected")
        void nineteenOrMoreDigits_isRejected(String hrp) {
            assertMalformed(TestInvoices.builder().hrp(hrp).build());
        }
    }

    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Network prefix")
    class Prefix {

        @ParameterizedTest(name = "{0} has no amount")
        @ValueSource(strings = {"lnbc", "lnbcrt", "lntb", "lntbs", "lnsb"})
        @DisplayName("an amountless human-readable part gives a null amount")
        void amountless_returnsNull(String hrp) {
            assertNull(parseHrp(hrp).amountMsat());
        }

        @ParameterizedTest(name = "{0} = {1} msat")
        @CsvSource({
                "lnbc100n,   10000",
                "lnbcrt100n, 10000",
                "lntb100n,   10000",
                "lntbs100n,  10000",
                "lnsb100n,   10000",
                "lnbcrt1u,   100000",
                "lntbs2500u, 250000000",
                "lntb20m,    2000000000",
        })
        @DisplayName("mainnet, testnet, signet, regtest and simnet prefixes are all read")
        void knownPrefixes_areAccepted(String hrp, long expectedMsat) {
            assertEquals(expectedMsat, parseHrp(hrp).amountMsat());
        }

        @ParameterizedTest(name = "{0} is rejected")
        @ValueSource(strings = {"lnxx100n", "bc100n", "lnb100n", "ln100n", "lnbcr100n", "lntbx100n"})
        @DisplayName("an unknown network prefix is rejected")
        void unknownPrefix_isRejected(String hrp) {
            assertMalformed(TestInvoices.builder().hrp(hrp).build());
        }

        @Test
        @DisplayName("an empty human-readable part is rejected")
        void emptyHrp_isRejected() {
            assertMalformed(TestInvoices.builder().hrp("").build());
        }
    }

    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Timestamp and expiry")
    class Expiry {

        @Test
        @DisplayName("without an x tag the expiry defaults to 3600 seconds after the timestamp")
        void noExpiryTag_defaultsToOneHour() {
            var invoice = parse(TestInvoices.builder().hrp("lnbc100n").timestamp(SPEC_TIMESTAMP).build());

            assertEquals(Instant.ofEpochSecond(SPEC_TIMESTAMP + 3600), invoice.expiresAt());
        }

        @ParameterizedTest(name = "x = {0} seconds")
        @ValueSource(longs = {0, 1, 31, 32, 60, 1023, 1024, 86_400, 604_800, 4_294_967_295L, 34_359_738_367L})
        @DisplayName("an explicit x tag sets the expiry exactly")
        void explicitExpiry_isHonoured(long seconds) {
            var invoice = parse(TestInvoices.builder().hrp("lnbc100n")
                    .timestamp(SPEC_TIMESTAMP).expirySeconds(seconds).build());

            assertEquals(Instant.ofEpochSecond(SPEC_TIMESTAMP + seconds), invoice.expiresAt());
        }

        @Test
        @DisplayName("the x tag is found after other tags (tag walk uses each tag's declared length)")
        void expiryAfterOtherTags_isFound() {
            var invoice = parse(TestInvoices.builder().hrp("lnbc100n").timestamp(SPEC_TIMESTAMP)
                    .rawTag(13, 1, 2, 3, 4, 5)           // description
                    .rawTag(19, new int[40])             // 40 words: needs the high length word
                    .rawTag(6, 1, 28)                    // x = 60
                    .build());

            assertEquals(Instant.ofEpochSecond(SPEC_TIMESTAMP + 60), invoice.expiresAt());
        }

        @Test
        @DisplayName("a 35-bit timestamp does not overflow")
        void largeTimestamp_isReadAsLong() {
            var timestamp = 34_359_738_367L; // 2^35 - 1, the largest the 7 words can carry
            var invoice = parse(TestInvoices.builder().hrp("lnbc100n").timestamp(timestamp).build());

            assertEquals(Instant.ofEpochSecond(timestamp + 3600), invoice.expiresAt());
        }

        @Test
        @DisplayName("every timestamp word contributes (value above 2^30 and below)")
        void timestampWords_allContribute() {
            for (var timestamp : new long[] {1, 31, 32, 1_023, 1_048_576, 1_073_741_824L, 5_000_000_000L}) {
                var invoice = parse(TestInvoices.builder().hrp("lnbc100n").timestamp(timestamp).build());
                assertEquals(Instant.ofEpochSecond(timestamp + 3600), invoice.expiresAt());
            }
        }

        @Test
        @DisplayName("a duplicate x tag is rejected")
        void duplicateExpiry_isRejected() {
            assertMalformed(TestInvoices.builder().hrp("lnbc100n").expirySeconds(60).expiryTags(2).build());
        }

        @Test
        @DisplayName("a duplicate x tag is rejected even when the two values agree and other tags sit between")
        void duplicateExpiryNonAdjacent_isRejected() {
            assertMalformed(TestInvoices.builder().hrp("lnbc100n").expirySeconds(60)
                    .rawTag(13, 1, 2, 3).rawTag(6, 1, 28).build());
        }

        @Test
        @DisplayName("an x tag of length 0 is rejected")
        void emptyExpiry_isRejected() {
            assertMalformed(TestInvoices.builder().hrp("lnbc100n").rawTag(6).build());
        }

        @Test
        @DisplayName("an x tag longer than 7 words is rejected")
        void tooLongExpiry_isRejected() {
            assertMalformed(TestInvoices.builder().hrp("lnbc100n").rawTag(6, new int[8]).build());
        }

        @Test
        @DisplayName("an x tag of exactly 7 words is accepted")
        void sevenWordExpiry_isAccepted() {
            var invoice = parse(TestInvoices.builder().hrp("lnbc100n").timestamp(SPEC_TIMESTAMP)
                    .rawTag(6, 0, 0, 0, 0, 0, 1, 1).build());

            assertEquals(Instant.ofEpochSecond(SPEC_TIMESTAMP + 33), invoice.expiresAt());
        }
    }

    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Structure")
    class Structure {

        @Test
        @DisplayName("a minimal invoice with no tags (7 timestamp + 104 signature words) is accepted")
        void minimalInvoice_isAccepted() {
            var invoice = parse(TestInvoices.builder().hrp("lnbc100n").withoutPaymentHash().build());

            assertEquals(10_000L, invoice.amountMsat());
        }

        @Test
        @DisplayName("fewer than 7 + 104 words is rejected")
        void truncated_isRejected() {
            assertMalformed(TestInvoices.builder().hrp("lnbc100n").withoutPaymentHash()
                    .signatureWords(103).build());
            assertMalformed(TestInvoices.builder().hrp("lnbc100n").signatureWords(0).build());
            assertMalformed(TestInvoices.builder().hrp("lnbc100n").signatureWords(50).build());
        }

        @Test
        @DisplayName("103 signature words is rejected: the last tag runs into the signature")
        void signatureTooShort_isRejected() {
            assertMalformed(TestInvoices.builder().hrp("lnbc100n").signatureWords(103).build());
        }

        @ParameterizedTest(name = "{0} signature words")
        @ValueSource(ints = {105, 106})
        @DisplayName("105 or 106 signature words is rejected: a tag header straddles the signature boundary")
        void signatureTooLong_isRejected(int words) {
            assertMalformed(TestInvoices.builder().hrp("lnbc100n").signatureWords(words).build());
        }

        @Test
        @DisplayName("a tag that declares more words than remain before the signature is rejected")
        void tagRunningIntoSignature_isRejected() {
            assertMalformed(TestInvoices.builder().hrp("lnbc100n")
                    .rawTagDeclaringLength(13, 5, 1, 2).build());
            assertMalformed(TestInvoices.builder().hrp("lnbc100n")
                    .rawTagDeclaringLength(13, 1023).build());
        }

        @Test
        @DisplayName("a tag that ends exactly where the signature begins is accepted")
        void tagEndingAtSignature_isAccepted() {
            var invoice = parse(TestInvoices.builder().hrp("lnbc100n")
                    .rawTagDeclaringLength(13, 2, 1, 2).build());

            assertEquals(10_000L, invoice.amountMsat());
        }

        @Test
        @DisplayName("an empty tag (header only, no data) right before the signature is accepted")
        void emptyTagAtEndOfRegion_isAccepted() {
            var invoice = parse(TestInvoices.builder().hrp("lnbc100n").rawTag(13).build());

            assertEquals(10_000L, invoice.amountMsat());
        }

        @Test
        @DisplayName("a data part shorter than the 6 checksum words is rejected")
        void noDataPart_isRejected() {
            assertMalformed("lnbc1");
            assertMalformed("lnbc1qqqqq");
        }

        @Test
        @DisplayName("an unknown tag type is skipped")
        void unknownTag_isIgnored() {
            var invoice = parse(TestInvoices.builder().hrp("lnbc100n").rawTag(31, 1, 2, 3).build());

            assertEquals(10_000L, invoice.amountMsat());
        }

        @Test
        @DisplayName("a 10,000 character invoice is accepted and 10,001 characters is rejected")
        void maximumLength_boundary() {
            var exactly = invoiceOfLength(10_000);
            var tooLong = invoiceOfLength(10_001);

            assertEquals(10_000, exactly.length());
            assertEquals(10_001, tooLong.length());
            assertEquals(10_000L, parse(exactly).amountMsat());
            assertMalformed(tooLong);
        }

        /** Pads with description tags (up to 1023 words each) until the invoice has this length. */
        private String invoiceOfLength(int length) {
            var base = TestInvoices.builder().hrp("lnbc100n").build().length();
            var remaining = length - base;
            var builder = TestInvoices.builder().hrp("lnbc100n");
            while (remaining > 0) {
                int chunk;
                if (remaining >= 1029) {
                    chunk = 1026;
                } else if (remaining > 1026) {
                    chunk = remaining - 3;
                } else {
                    chunk = remaining;
                }
                builder.rawTag(13, new int[chunk - 3]);
                remaining -= chunk;
            }
            return builder.build();
        }
    }

    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Bech32 checksum and characters")
    class Bech32Encoding {

        @ParameterizedTest(name = "data offset {0}")
        @ValueSource(ints = {0, 1, 20, 100, -7, -1})
        @DisplayName("flipping one data or checksum character is rejected")
        void flippedCharacter_isRejected(int offset) {
            var valid = TestInvoices.mainnetForSats(100);
            var index = offset >= 0 ? dataStart(valid) + offset : valid.length() + offset;
            var original = valid.charAt(index);
            var replacement = original == 'q' ? 'p' : 'q';

            assertMalformed(replaceAt(valid, index, replacement));
        }

        @Test
        @DisplayName("changing a human-readable-part character without fixing the checksum is rejected")
        void changedHrp_isRejected() {
            var valid = TestInvoices.mainnetForSats(100);

            // 100 sats is lnbc1000n; turn it into lnbc9000n without re-computing the checksum.
            assertTrue(valid.startsWith("lnbc1000n1"));
            assertMalformed("lnbc9000n" + valid.substring("lnbc1000n".length()));
        }

        @Test
        @DisplayName("an invalid bech32 character reports its data index and does not echo the character")
        void invalidCharacter_reportsIndexNotCharacter() {
            var valid = TestInvoices.mainnetForSats(100);
            var invalid = replaceAt(valid, dataStart(valid) + 12, '~');

            var e = assertThrows(LnurlInvoiceRejectedException.class, () -> parse(invalid));

            assertEquals(Reason.MALFORMED, e.getReason());
            assertTrue(e.getMessage().contains("data index 12"), e.getMessage());
            assertFalse(e.getMessage().contains("~"), e.getMessage());
            assertFalse(e.getMessage().contains(invalid), e.getMessage());
        }

        @ParameterizedTest(name = "character ''{0}''")
        @ValueSource(chars = {'b', 'i', 'o', '!', ' ', '-', '_'})
        @DisplayName("characters outside the bech32 charset are rejected")
        void characterOutsideCharset_isRejected(char c) {
            var valid = TestInvoices.mainnetForSats(100);

            assertMalformed(replaceAt(valid, dataStart(valid) + 3, c));
        }

        @Test
        @DisplayName("a string without a bech32 separator is rejected")
        void noSeparator_isRejected() {
            assertMalformed("lnbcqpzry");
            assertMalformed("lnbc");
            assertMalformed("qpzryqpzryqpzry");
        }

        @Test
        @DisplayName("a separator in the first position (empty prefix) is rejected")
        void separatorFirst_isRejected() {
            assertMalformed("1qpzryqpzryqpzry");
        }

        @Test
        @DisplayName("mixed upper and lower case is rejected")
        void mixedCase_isRejected() {
            var valid = TestInvoices.mainnetForSats(100);

            assertMalformed(replaceAt(valid, 2, 'B'));
            assertMalformed(valid.substring(0, 20) + valid.substring(20).toUpperCase());
        }

        @Test
        @DisplayName("an all upper-case invoice is accepted and equals the lower-case result")
        void upperCase_isAccepted() {
            var lower = TestInvoices.builder().hrp("lnbc2500u").timestamp(SPEC_TIMESTAMP)
                    .expirySeconds(60).build();

            var fromLower = parse(lower);
            var fromUpper = parse(lower.toUpperCase());

            assertEquals(250_000_000L, fromUpper.amountMsat());
            assertEquals(fromLower.amountMsat(), fromUpper.amountMsat());
            assertEquals(fromLower.expiresAt(), fromUpper.expiresAt());
        }

        @ParameterizedTest(name = "U+{0}")
        @ValueSource(strings = {"00E9", "212A", "FF51", "0131", "1F600"})
        @DisplayName("a non-ASCII character is rejected, including ones that lower-case to ASCII")
        void nonAscii_isRejected(String codePointHex) {
            var valid = TestInvoices.mainnetForSats(100);
            var replacement = new String(Character.toChars(Integer.parseInt(codePointHex, 16)));
            var invoice = valid.substring(0, dataStart(valid) + 5) + replacement
                    + valid.substring(dataStart(valid) + 6);

            assertMalformed(invoice);
        }

        @Test
        @DisplayName("a trailing non-ASCII character is rejected")
        void trailingNonAscii_isRejected() {
            assertMalformed(TestInvoices.mainnetForSats(100) + "é");
        }

        @Test
        @DisplayName("null, empty and over-long input is rejected")
        void nullEmptyAndTooLong_areRejected() {
            assertMalformed(null);
            assertMalformed("");
            assertMalformed("a".repeat(10_001));
            assertMalformed("q".repeat(100_000));
        }

        @Test
        @DisplayName("surrounding whitespace is not trimmed")
        void whitespace_isRejected() {
            var valid = TestInvoices.mainnetForSats(100);

            assertMalformed(valid + " ");
            assertMalformed(" " + valid);
            assertMalformed(valid + "\n");
        }

        @Test
        @DisplayName("a rejection message never contains the invoice text")
        void rejection_neverEchoesInput() {
            var valid = TestInvoices.mainnetForSats(100);
            var corrupted = replaceAt(valid, valid.length() - 1, valid.endsWith("q") ? 'p' : 'q');

            var e = assertThrows(LnurlInvoiceRejectedException.class, () -> parse(corrupted));

            assertFalse(e.getMessage().contains(corrupted));
            assertFalse(e.getMessage().contains(valid.substring(10, 30)));
        }
    }

    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Independently produced vector")
    class SpecVector {

        /** First example of the BOLT11 specification: no amount, a donation request. */
        private static final String SPEC_DONATION =
                "lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d73gafnh3cax9rn449d9p5uxz9ezhhypd0elx87sjle52x86fux2ypatgddc6k63n7erqz25le42c4u4ecky03ylcqca784w";

        @Test
        @DisplayName("the BOLT11 specification donation invoice parses: no amount, timestamp 1496314658, default expiry")
        void specDonation_parses() {
            var invoice = parse(SPEC_DONATION);

            assertNull(invoice.amountMsat());
            assertEquals(Instant.ofEpochSecond(SPEC_TIMESTAMP + 3600), invoice.expiresAt());
        }

        // The examples below are copied verbatim from the BOLT11 specification, so they are
        // encoded by a third party and not by this repository's own test encoder.
        private static final String SPEC_COFFEE_60S =
                "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh";
        private static final String SPEC_HASHED_20M =
                "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrsgq7ea976txfraylvgzuxs8kgcw23ezlrszfnh8r6qtfpr6cxga50aj6txm9rxrydzd06dfeawfk6swupvz4erwnyutnjq7x39ymw6j38gp7ynn44";
        private static final String SPEC_TESTNET_20M =
                "lntb20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e20v6pu37c5d9vax37wxq72un989qrsgqdj545axuxtnfemtpwkc45hx9d2ft7x04mt8q7y6t0k2dge9e7h8kpy9p34ytyslj3yu569aalz2xdk8xkd7ltxqld94u8h2esmsmacgpghe9k8";
        private static final String SPEC_PICO_ONE_WEEK =
                "lnbc9678785340p1pwmna7lpp5gc3xfm08u9qy06djf8dfflhugl6p7lgza6dsjxq454gxhj9t7a0sd8dgfkx7cmtwd68yetpd5s9xar0wfjn5gpc8qhrsdfq24f5ggrxdaezqsnvda3kkum5wfjkzmfqf3jkgem9wgsyuctwdus9xgrcyqcjcgpzgfskx6eqf9hzqnteypzxz7fzypfhg6trddjhygrcyqezcgpzfysywmm5ypxxjemgw3hxjmn8yptk7untd9hxwg3q2d6xjcmtv4ezq7pqxgsxzmnyyqcjqmt0wfjjq6t5v4khxsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsxqyjw5qcqp2rzjq0gxwkzc8w6323m55m4jyxcjwmy7stt9hwkwe2qxmy8zpsgg7jcuwz87fcqqeuqqqyqqqqlgqqqqn3qq9q9qrsgqrvgkpnmps664wgkp43l22qsgdw4ve24aca4nymnxddlnp8vh9v2sdxlu5ywdxefsfvm0fq3sesf08uf6q9a2ke0hc9j6z6wlxg5z5kqpu2v9wz";
        private static final String SPEC_BAD_CHECKSUM =
                "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrnt";
        private static final String SPEC_NO_SEPARATOR =
                "pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrny";
        private static final String SPEC_MIXED_CASE =
                "LNBC2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrny";
        private static final String SPEC_TOO_SHORT =
                "lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6na6hlh";
        private static final String SPEC_INVALID_MULTIPLIER =
                "lnbc2500x1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpusp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9qrsgqrrzc4cvfue4zp3hggxp47ag7xnrlr8vgcmkjxk3j5jqethnumgkpqp23z9jclu3v0a7e0aruz366e9wqdykw6dxhdzcjjhldxq0w6wgqcnu43j";
        private static final String SPEC_SUB_MILLISATOSHI =
                "lnbc2500000001p1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpusp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9qrsgq0lzc236j96a95uv0m3umg28gclm5lqxtqqwk32uuk4k6673k6n5kfvx3d2h8s295fad45fdhmusm8sjudfhlf6dcsxmfvkeywmjdkxcp99202x";

        @Test
        @DisplayName("spec: lnbc2500u (the $3 coffee) is 250,000,000 msat and expires after 60 seconds")
        void specCoffee_amountAndExpiry() {
            var invoice = parse(SPEC_COFFEE_60S);

            assertEquals(250_000_000L, invoice.amountMsat());
            assertEquals(Instant.ofEpochSecond(SPEC_TIMESTAMP + 60), invoice.expiresAt());
        }

        @Test
        @DisplayName("spec: lnbc20m with a description hash is 2,000,000,000 msat")
        void specHashed_amount() {
            assertEquals(2_000_000_000L, parse(SPEC_HASHED_20M).amountMsat());
        }

        @Test
        @DisplayName("spec: lntb20m (testnet, with a fallback address) is 2,000,000,000 msat")
        void specTestnet_amount() {
            assertEquals(2_000_000_000L, parse(SPEC_TESTNET_20M).amountMsat());
        }

        @Test
        @DisplayName("spec: lnbc9678785340p is 967,878,534 msat and expires one week after 1572468703")
        void specPico_amountAndExpiry() {
            var invoice = parse(SPEC_PICO_ONE_WEEK);

            assertEquals(967_878_534L, invoice.amountMsat());
            assertEquals(Instant.ofEpochSecond(1_572_468_703L + 604_800L), invoice.expiresAt());
        }

        @ParameterizedTest(name = "invalid vector #{index}")
        @ValueSource(strings = {SPEC_BAD_CHECKSUM, SPEC_NO_SEPARATOR, SPEC_MIXED_CASE, SPEC_TOO_SHORT,
                SPEC_INVALID_MULTIPLIER, SPEC_SUB_MILLISATOSHI})
        @DisplayName("the invalid invoices listed in the specification are refused as MALFORMED")
        void specInvalid_refused(String invoice) {
            assertMalformed(invoice);
        }
    }

    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Hostile input")
    class HostileInput {

        private static final String VALID = TestInvoices.mainnetForSats(100);

        @Test
        @DisplayName("a lightning: URI prefix is refused (the provider must return the bare invoice)")
        void lightningPrefix_refused() {
            assertMalformed("lightning:" + VALID);
        }

        @Test
        @DisplayName("surrounding whitespace is refused, not trimmed")
        void whitespace_refused() {
            assertMalformed(" " + VALID);
            assertMalformed(VALID + "\n");
        }

        @Test
        @DisplayName("an embedded NUL in the human-readable part or the data part is refused")
        void nul_refused() {
            assertMalformed("lnbc100n\0" + VALID.substring(8));
            assertMalformed(VALID.substring(0, 20) + "\0" + VALID.substring(21));
        }

        @ParameterizedTest(name = "{0}")
        @ValueSource(strings = {"lnzzcanaryzz100n", "lnbc100nzzcanary", "lnbczzcanaryzz"})
        @DisplayName("provider text planted in the human-readable part never appears in the message")
        void canary_inHrp_neverEchoed(String hrp) {
            var invoice = TestInvoices.builder().hrp(hrp).build();

            var e = assertThrows(LnurlInvoiceRejectedException.class, () -> parse(invoice));

            assertNoFragmentEchoed(invoice, e.getMessage());
            assertFalse(e.getMessage().toLowerCase().contains("canary"), e.getMessage());
            assertFalse(e.getMessage().contains(hrp), e.getMessage());
        }

        @Test
        @DisplayName("provider text planted in the data part never appears in the message")
        void canary_inData_neverEchoed() {
            var invoice = "lnbc100n1zzcanaryzzbzzcanaryzz";

            var e = assertThrows(LnurlInvoiceRejectedException.class, () -> parse(invoice));

            assertNoFragmentEchoed(invoice, e.getMessage());
            assertFalse(e.getMessage().toLowerCase().contains("canary"), e.getMessage());
        }
    }

    /** No 8-character window of the provider's text may appear in an exception message or log line. */
    static void assertNoFragmentEchoed(String providerText, String message) {
        for (int i = 0; i + 8 <= providerText.length(); i++) {
            var fragment = providerText.substring(i, i + 8);
            assertFalse(message.contains(fragment),
                    "message echoes provider text fragment '" + fragment + "': " + message);
        }
    }
}
