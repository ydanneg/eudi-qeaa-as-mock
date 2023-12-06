package ee.ria.eudi.qeaa.as.model;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record TokenResponse(String accessToken,
                            String tokenType,
                            String cNonce,
                            Long cNonceExpiresIn,
                            AuthorizationDetails authorizationDetails) {

}
