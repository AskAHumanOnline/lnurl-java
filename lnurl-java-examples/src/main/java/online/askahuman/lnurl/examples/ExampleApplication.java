package online.askahuman.lnurl.examples;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Example Spring Boot application demonstrating lnurl-java library usage.
 *
 * <p>Starts on port 8090 (configurable via application.yml) and exposes
 * LNURL-auth and LNURL-pay example endpoints.</p>
 */
@SpringBootApplication
public class ExampleApplication {

    public static void main(String[] args) {
        SpringApplication.run(ExampleApplication.class, args);
    }
}
