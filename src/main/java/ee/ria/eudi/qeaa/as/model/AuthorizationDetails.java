package ee.ria.eudi.qeaa.as.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.Embeddable;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@NoArgsConstructor
@Embeddable
public class AuthorizationDetails {
    private String type;
    private String format;
    private String doctype;
    @JsonProperty("credential_configuration_id")
    private String credentialConfigurationId;
    private List<String> locations;

    @Builder
    @SuppressWarnings("unchecked")
    public AuthorizationDetails(Map<?, ?> authorizationDetails) {
        type = (String) authorizationDetails.get("type");
        format = (String) authorizationDetails.get("format");
        doctype = (String) authorizationDetails.get("doctype");
        credentialConfigurationId = (String) authorizationDetails.get("credential_configuration_id");
        locations = (List<String>) authorizationDetails.get("locations");
    }
}
