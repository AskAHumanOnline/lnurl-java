package online.askahuman.lnurl.spring;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for the lnurl-java library.
 *
 * <p>Bind to {@code lnurl.*} in application.yml / application.properties.</p>
 */
@ConfigurationProperties(prefix = "lnurl")
public class LnurlProperties {

    private Auth auth = new Auth();
    private Pay pay = new Pay();
    private Lnd lnd = new Lnd();

    public Auth getAuth() { return auth; }
    public void setAuth(Auth auth) { this.auth = auth; }

    public Pay getPay() { return pay; }
    public void setPay(Pay pay) { this.pay = pay; }

    public Lnd getLnd() { return lnd; }
    public void setLnd(Lnd lnd) { this.lnd = lnd; }

    /**
     * LNURL-auth (LUD-04) settings.
     */
    public static class Auth {
        /** Base URL used when building the LNURL callback URL. */
        private String baseUrl = "http://localhost:8080";

        /** How long k1 challenges remain valid (seconds). Default: 300 (5 minutes). */
        private int challengeExpirySeconds = 300;

        public String getBaseUrl() { return baseUrl; }
        public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }

        public int getChallengeExpirySeconds() { return challengeExpirySeconds; }
        public void setChallengeExpirySeconds(int challengeExpirySeconds) { this.challengeExpirySeconds = challengeExpirySeconds; }
    }

    /**
     * LNURL-pay (LUD-06) settings.
     */
    public static class Pay {
        /** If true, LNURL resolution failures throw an exception. If false, a mock invoice is returned. */
        private boolean failOnResolutionError = true;

        public boolean isFailOnResolutionError() { return failOnResolutionError; }
        public void setFailOnResolutionError(boolean failOnResolutionError) { this.failOnResolutionError = failOnResolutionError; }
    }

    /**
     * LND connection settings.
     */
    public static class Lnd {
        /** LND host. */
        private String host = "localhost";

        /**
         * LND REST API port. Default 8181 avoids conflict with Spring Boot's default server
         * port (8080). LND's built-in default is also 8080 — set explicitly when running
         * both on the same host.
         */
        private int restPort = 8181;

        /** Path to the LND admin macaroon file. */
        private String macaroonPath = "";

        /** Path to the LND TLS certificate file. */
        private String tlsCertPath = "";

        public String getHost() { return host; }
        public void setHost(String host) { this.host = host; }

        public int getRestPort() { return restPort; }
        public void setRestPort(int restPort) { this.restPort = restPort; }

        public String getMacaroonPath() { return macaroonPath; }
        public void setMacaroonPath(String macaroonPath) { this.macaroonPath = macaroonPath; }

        public String getTlsCertPath() { return tlsCertPath; }
        public void setTlsCertPath(String tlsCertPath) { this.tlsCertPath = tlsCertPath; }
    }
}
