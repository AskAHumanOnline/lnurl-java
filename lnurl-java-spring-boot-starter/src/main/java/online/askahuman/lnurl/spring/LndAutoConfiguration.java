package online.askahuman.lnurl.spring;

import online.askahuman.lnurl.lnd.LndClient;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Spring Boot auto-configuration for {@link LndClient}.
 *
 * <p>Only activates when {@code lnurl.lnd.host} is set. Reads the macaroon file
 * and TLS certificate from the configured paths.</p>
 */
@AutoConfiguration
@EnableConfigurationProperties(LnurlProperties.class)
@ConditionalOnProperty(prefix = "lnurl.lnd", name = "host")
public class LndAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public LndClient lndClient(LnurlProperties props) {
        LnurlProperties.Lnd lnd = props.getLnd();
        return LndClient.withMacaroonFile(
                lnd.getHost(),
                lnd.getRestPort(),
                lnd.getMacaroonPath(),
                lnd.getTlsCertPath()
        );
    }
}
