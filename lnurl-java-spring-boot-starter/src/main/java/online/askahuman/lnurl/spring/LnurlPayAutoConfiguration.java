package online.askahuman.lnurl.spring;

import online.askahuman.lnurl.LnurlPayClient;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Spring Boot auto-configuration for {@link LnurlPayClient}.
 *
 * <p>Registers an {@link LnurlPayClient} bean using the default 10-second timeout HttpClient.
 * The {@code lnurl.pay.fail-on-resolution-error} property controls whether resolution
 * failures throw exceptions (default: true) or return mock invoices.</p>
 */
@AutoConfiguration
@EnableConfigurationProperties(LnurlProperties.class)
public class LnurlPayAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public LnurlPayClient lnurlPayClient(LnurlProperties props) {
        return LnurlPayClient.create(props.getPay().isFailOnResolutionError());
    }
}
