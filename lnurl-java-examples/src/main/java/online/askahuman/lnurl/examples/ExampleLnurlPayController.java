package online.askahuman.lnurl.examples;

import online.askahuman.lnurl.LnurlPayClient;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Example controller demonstrating LNURL-pay (LUD-06) resolution.
 *
 * <p>Endpoints:</p>
 * <ul>
 *   <li>GET /pay/{lightningAddress}/{amountSats} -- Resolve a Lightning address to a BOLT11 invoice</li>
 * </ul>
 */
@RestController
@RequestMapping("/pay")
public class ExampleLnurlPayController {

    private final LnurlPayClient lnurlPayClient;

    public ExampleLnurlPayController(LnurlPayClient lnurlPayClient) {
        this.lnurlPayClient = lnurlPayClient;
    }

    @GetMapping("/{lightningAddress}/{amountSats}")
    public Map<String, String> getInvoice(
            @PathVariable String lightningAddress,
            @PathVariable int amountSats) {
        String invoice = lnurlPayClient.resolveLightningAddress(lightningAddress, amountSats);
        return Map.of("invoice", invoice);
    }
}
