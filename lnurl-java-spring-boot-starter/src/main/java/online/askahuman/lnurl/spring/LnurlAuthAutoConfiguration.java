package online.askahuman.lnurl.spring;

import online.askahuman.lnurl.LnurlAuthService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

/**
 * Spring Boot auto-configuration for {@link LnurlAuthService}.
 *
 * <p>Registers an {@link LnurlAuthService} bean and schedules periodic cleanup
 * of expired LNURL-auth challenges.</p>
 */
@AutoConfiguration
@EnableConfigurationProperties(LnurlProperties.class)
public class LnurlAuthAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public LnurlAuthService lnurlAuthService(LnurlProperties props) {
        return new LnurlAuthService(props.getAuth().getChallengeExpirySeconds());
    }

    @Configuration
    @EnableScheduling
    static class LnurlAuthSchedulingConfig {
        private final LnurlAuthService lnurlAuthService;

        LnurlAuthSchedulingConfig(LnurlAuthService lnurlAuthService) {
            this.lnurlAuthService = lnurlAuthService;
        }

        @Scheduled(fixedDelay = 60_000)
        public void cleanupExpiredChallenges() {
            lnurlAuthService.cleanupExpiredChallenges();
        }
    }
}
