package online.askahuman.lnurl.examples;

import online.askahuman.lnurl.Bech32Utils;
import online.askahuman.lnurl.LnurlAuthService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Example controller demonstrating LNURL-auth (LUD-04) flow.
 *
 * <p>Endpoints:</p>
 * <ul>
 *   <li>GET /auth/lnurl -- Generate k1 challenge + bech32-encoded LNURL string</li>
 *   <li>GET /auth/callback -- Two-step wallet callback (discovery + auth)</li>
 *   <li>GET /auth/status/{k1} -- Poll for authentication result</li>
 * </ul>
 */
@RestController
@RequestMapping("/auth")
public class ExampleLnurlAuthController {

    private final LnurlAuthService lnurlAuthService;
    private final String baseUrl;

    public ExampleLnurlAuthController(
            LnurlAuthService lnurlAuthService,
            @Value("${lnurl.auth.base-url:http://localhost:8090}") String baseUrl) {
        this.lnurlAuthService = lnurlAuthService;
        this.baseUrl = baseUrl;
    }

    @GetMapping("/lnurl")
    public Map<String, String> getLnurl() {
        String k1 = lnurlAuthService.generateChallenge();
        String callbackUrl = baseUrl + "/auth/callback?tag=login&k1=" + k1;
        String lnurl = Bech32Utils.encodeLnurl(callbackUrl);
        return Map.of("k1", k1, "lnurl", lnurl);
    }

    @GetMapping("/callback")
    public Map<String, Object> callback(
            @RequestParam String k1,
            @RequestParam(required = false) String sig,
            @RequestParam(required = false) String key) {
        if (sig == null || key == null) {
            // Discovery step
            if (!lnurlAuthService.isValidChallenge(k1)) {
                return Map.of("status", "ERROR", "reason", "Unknown or expired k1");
            }
            return Map.of("tag", "login", "k1", k1, "action", "login");
        }
        // Auth step
        boolean verified = lnurlAuthService.verifyCallback(k1, sig, key);
        if (!verified) {
            return Map.of("status", "ERROR", "reason", "Signature verification failed");
        }
        return Map.of("status", "OK");
    }

    @GetMapping("/status/{k1}")
    public Map<String, Object> status(@PathVariable String k1) {
        String linkingKey = lnurlAuthService.getAuthenticatedKey(k1);
        if (linkingKey == null) {
            return Map.of("authenticated", false);
        }
        return Map.of("authenticated", true, "linkingKey", linkingKey);
    }
}
