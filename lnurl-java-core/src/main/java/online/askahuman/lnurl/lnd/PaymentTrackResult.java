package online.askahuman.lnurl.lnd;

/**
 * Current state of a payment as reported by LND's payment tracker.
 *
 * @param outcome         where the payment stands
 * @param paymentHash     SHA-256 payment hash (hex)
 * @param paymentPreimage proof of payment (hex), only for {@link Outcome#SUCCEEDED}
 * @param failureReason   LND failure-reason code, only for {@link Outcome#FAILED}
 */
public record PaymentTrackResult(
        Outcome outcome,
        String paymentHash,
        String paymentPreimage,
        String failureReason
) {

    /** Where a tracked payment stands. */
    public enum Outcome {
        /** The payment settled and the preimage is known. */
        SUCCEEDED,
        /** The payment definitively failed; no funds left the node. */
        FAILED,
        /** The payment is initiated or in flight and may still settle or fail. */
        IN_FLIGHT,
        /** LND has no record of this payment: it was never sent. */
        NOT_INITIATED
    }
}
