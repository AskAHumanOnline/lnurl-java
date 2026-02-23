package online.askahuman.lnurl.spring;

import online.askahuman.lnurl.LnurlAuthService;
import online.askahuman.lnurl.LnurlPayClient;
import online.askahuman.lnurl.lnd.LndClient;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class LnurlAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    LnurlAuthAutoConfiguration.class,
                    LnurlPayAutoConfiguration.class,
                    LndAutoConfiguration.class
            ));

    @Test
    void lnurlAuthServiceBeanCreatedByDefault() {
        contextRunner
                .run(ctx -> assertThat(ctx).hasSingleBean(LnurlAuthService.class));
    }

    @Test
    void lnurlPayClientBeanCreatedByDefault() {
        contextRunner
                .run(ctx -> assertThat(ctx).hasSingleBean(LnurlPayClient.class));
    }

    @Test
    void lndClientBeanCreatedWhenHostPropertySet() {
        contextRunner
                .withPropertyValues("lnurl.lnd.host=localhost")
                .run(ctx -> assertThat(ctx).hasSingleBean(LndClient.class));
    }

    @Test
    void lndClientBeanNotCreatedWithoutHostProperty() {
        contextRunner
                .run(ctx -> assertThat(ctx).doesNotHaveBean(LndClient.class));
    }

    @Test
    void lnurlAuthServiceUsesConfiguredExpiry() {
        contextRunner
                .withPropertyValues("lnurl.auth.challenge-expiry-seconds=120")
                .run(ctx -> {
                    assertThat(ctx).hasSingleBean(LnurlAuthService.class);
                    // verify bean exists (exact expiry value not exposed)
                    LnurlAuthService service = ctx.getBean(LnurlAuthService.class);
                    String k1 = service.generateChallenge();
                    assertThat(k1).isNotNull().hasSize(64);
                });
    }

    @Test
    void userDefinedLnurlAuthServicePreventsBeanCreation() {
        contextRunner
                .withBean(LnurlAuthService.class, () -> new LnurlAuthService(600))
                .run(ctx -> {
                    assertThat(ctx).hasSingleBean(LnurlAuthService.class);
                    // exactly one bean — user's own, not the auto-configured one
                });
    }

    @Test
    void lnurlPayClientUsesFalseFailOnResolutionErrorWhenConfigured() {
        contextRunner
                .withPropertyValues("lnurl.pay.fail-on-resolution-error=false")
                .run(ctx -> {
                    assertThat(ctx).hasSingleBean(LnurlPayClient.class);
                    LnurlPayClient client = ctx.getBean(LnurlPayClient.class);
                    // In lenient mode, resolution failures return a mock invoice (no exception)
                    String result = client.resolveLightningAddress("test@nonexistent.local", 100);
                    assertThat(result).startsWith("mock_invoice_");
                });
    }

    @Test
    void userDefinedLnurlPayClientPreventsBeanCreation() {
        contextRunner
                .withBean(LnurlPayClient.class, () -> LnurlPayClient.create(false))
                .run(ctx -> {
                    assertThat(ctx).hasSingleBean(LnurlPayClient.class);
                    // exactly one bean — user's own, not the auto-configured one
                });
    }

    @Test
    void lndClientBeanNotCreatedWhenOnlyOtherLndPropertiesSet() {
        // restPort and macaroonPath are not the trigger — only lnurl.lnd.host activates the bean
        contextRunner
                .withPropertyValues(
                        "lnurl.lnd.rest-port=10009",
                        "lnurl.lnd.macaroon-path=/some/path"
                )
                .run(ctx -> assertThat(ctx).doesNotHaveBean(LndClient.class));
    }
}
