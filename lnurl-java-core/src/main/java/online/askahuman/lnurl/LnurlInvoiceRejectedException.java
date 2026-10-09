package online.askahuman.lnurl;

/**
 * Thrown when the invoice a LNURL-pay provider returned is not acceptable for the payment that was
 * requested (malformed, amountless, wrong amount or expired), so it must not be paid.
 *
 * <p>The provider is not trusted: this exception signals that its answer failed validation, not
 * that the network misbehaved. {@link LnurlPayClient} therefore always throws it, even when
 * configured with {@code failOnResolutionError=false} (which otherwise substitutes a mock invoice
 * for resolution failures).</p>
 *
 * <p>The message contains only the {@link Reason} and a fixed description. It never repeats
 * provider-supplied text, so it is safe to log.</p>
 */
public final class LnurlInvoiceRejectedException extends LnurlException {

    /** Why the invoice was refused. */
    public enum Reason {
        /** Not a well-formed, checksum-valid BOLT11 invoice. */
        MALFORMED,
        /** The invoice carries no amount, so the payer would choose what to send. */
        AMOUNTLESS,
        /** The invoice amount differs from the amount requested. */
        AMOUNT_MISMATCH,
        /** The invoice has already expired. */
        EXPIRED
    }

    private final Reason reason;

    LnurlInvoiceRejectedException(Reason reason, String detail) {
        super("LNURL-pay invoice rejected (" + reason + "): " + detail);
        this.reason = reason;
    }

    /**
     * @return why the invoice was refused
     */
    public Reason getReason() {
        return reason;
    }
}
