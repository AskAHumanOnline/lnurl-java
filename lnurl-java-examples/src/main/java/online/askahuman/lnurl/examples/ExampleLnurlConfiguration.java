package online.askahuman.lnurl.examples;

import online.askahuman.lnurl.LnurlAuthService;
import online.askahuman.lnurl.LnurlPayClient;
import online.askahuman.lnurl.lnd.LndClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Example configuration that overrides auto-configured beans with example-specific settings.
 *
 * <p>This demonstrates how consuming applications can provide their own bean definitions
 * to override the auto-configured defaults from the starter.</p>
 */
@Configuration
public class ExampleLnurlConfiguration {

    @Bean
    public LnurlAuthService lnurlAuthService() {
        return new LnurlAuthService(300);
    }

    @Bean
    public LnurlPayClient lnurlPayClient() {
        return LnurlPayClient.create(false); // lenient mode for examples
    }

    @Bean
    public LndClient lndClient() {
        // Mock mode -- no real LND needed for examples
        return LndClient.withMacaroonFile("localhost", 8080, "/nonexistent/path", "/nonexistent/path");
    }
}
