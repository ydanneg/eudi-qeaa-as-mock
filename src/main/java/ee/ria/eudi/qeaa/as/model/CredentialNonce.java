package ee.ria.eudi.qeaa.as.model;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record CredentialNonce(
    String cNonce,
    long cNonceExpiresIn) {
}
