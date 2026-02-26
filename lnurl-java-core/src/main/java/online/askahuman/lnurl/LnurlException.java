package online.askahuman.lnurl;

/**
 * Base exception for LNURL protocol errors.
 *
 * <p>Thrown when LNURL operations fail due to protocol errors, network issues, or invalid
 * remote responses — as distinct from {@link IllegalArgumentException} (invalid caller input)
 * and {@link IllegalStateException} (configuration errors).</p>
 *
 * <p>Since this class extends {@link RuntimeException}, existing code that catches
 * {@code RuntimeException} continues to work without modification.</p>
 */
public class LnurlException extends RuntimeException {

    /**
     * Constructs a new LnurlException with the given message.
     *
     * @param message human-readable description of the error
     */
    public LnurlException(String message) {
        super(message);
    }

    /**
     * Constructs a new LnurlException with the given message and cause.
     *
     * @param message human-readable description of the error
     * @param cause   the underlying exception that triggered this error
     */
    public LnurlException(String message, Throwable cause) {
        super(message, cause);
    }
}
