package online.askahuman.lnurl.spring;

import online.askahuman.lnurl.LnurlAuthService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Spring Boot auto-configuration for {@link LnurlAuthService}.
 *
 * <p>Registers an {@link LnurlAuthService} bean and a dedicated single-thread
 * {@link ScheduledExecutorService} for periodic cleanup of expired LNURL-auth
 * challenges. Does <em>not</em> use {@code @EnableScheduling} to avoid
 * application-wide side-effects in consumer projects.</p>
 */
@AutoConfiguration
@EnableConfigurationProperties(LnurlProperties.class)
public class LnurlAuthAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public LnurlAuthService lnurlAuthService(LnurlProperties props) {
        return new LnurlAuthService(props.getAuth().getChallengeExpirySeconds());
    }

    /**
     * Dedicated single-thread scheduler for expired challenge cleanup.
     * Does not use @EnableScheduling to avoid affecting the consumer application's
     * task scheduler configuration.
     */
    @Bean(destroyMethod = "shutdown")
    @ConditionalOnMissingBean(name = "lnurlAuthCleanupScheduler")
    public ScheduledExecutorService lnurlAuthCleanupScheduler(LnurlAuthService lnurlAuthService) {
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "lnurl-auth-cleanup");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleWithFixedDelay(
                lnurlAuthService::cleanupExpiredChallenges, 60, 60, TimeUnit.SECONDS);
        return scheduler;
    }
}
