package online.askahuman.lnurl.lnd;

import online.askahuman.lnurl.LnurlException;

/**
 * Thrown when it cannot be determined whether a payment was sent: the request timed out, the
 * connection dropped mid-request, LND answered with an error or an unrecognised status, or the
 * payment is still in flight.
 *
 * <p>The payment may still settle. Callers must not pay a different invoice for the same
 * obligation; resolve the outcome with {@link LndClient#trackPayment(String)} first. The
 * message never repeats text received from LND, so it is safe to log.</p>
 */
public final class PaymentOutcomeUnknownException extends LnurlException {

    PaymentOutcomeUnknownException(String detail) {
        super("LND payment outcome unknown: " + detail);
    }

    PaymentOutcomeUnknownException(String detail, Throwable cause) {
        super("LND payment outcome unknown: " + detail, cause);
    }
}
