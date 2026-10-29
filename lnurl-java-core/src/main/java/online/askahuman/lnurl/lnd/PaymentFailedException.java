package online.askahuman.lnurl.lnd;

import online.askahuman.lnurl.LnurlException;

import java.util.regex.Pattern;

/**
 * Thrown when LND reports that a payment definitively failed: no funds left the node and
 * the same invoice can safely be paid again.
 *
 * <p>Contrast with {@link PaymentOutcomeUnknownException}, where the payment may still settle.
 * The message holds only LND's failure-reason code, so it is safe to log.</p>
 */
public final class PaymentFailedException extends LnurlException {

    private static final Pattern REASON_CODE = Pattern.compile("[A-Z_]{1,64}");

    private final String failureReason;

    PaymentFailedException(String reason) {
        super("LND payment failed: " + sanitize(reason));
        this.failureReason = sanitize(reason);
    }

    /**
     * @return LND's failure-reason code (for example {@code FAILURE_REASON_NO_ROUTE}), or
     *         {@code UNKNOWN} when LND sent nothing recognisable
     */
    public String getFailureReason() {
        return failureReason;
    }

    private static String sanitize(String reason) {
        return reason != null && REASON_CODE.matcher(reason).matches() ? reason : "UNKNOWN";
    }
}
