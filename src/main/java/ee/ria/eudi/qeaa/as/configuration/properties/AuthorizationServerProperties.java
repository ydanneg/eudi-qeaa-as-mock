package ee.ria.eudi.qeaa.as.configuration.properties;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@Validated
@ConfigurationProperties(prefix = "eudi")
public record AuthorizationServerProperties(
    AuthorizationServer as) {

    public record AuthorizationServer(
        @NotBlank
        @Pattern(regexp = ".*(?<!/)$")
        String baseUrl,
        @NotNull
        TimeToLive ttl) {
    }

    public record TimeToLive(
        @NotNull
        Duration requestUri) {
    }
}
