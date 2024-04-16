package ee.ria.eudi.qeaa.as.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.State;
import ee.ria.eudi.qeaa.as.configuration.properties.AuthorizationServerProperties;
import ee.ria.eudi.qeaa.as.model.AuthorizationDetails;
import ee.ria.eudi.qeaa.as.model.ParResponse;
import ee.ria.eudi.qeaa.as.model.Session;
import ee.ria.eudi.qeaa.as.repository.SessionRepository;
import ee.ria.eudi.qeaa.as.validation.AuthorizationRequestValidator;
import ee.ria.eudi.qeaa.as.validation.ClientAttestationValidator;
import jakarta.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.tuple.Pair;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.text.ParseException;
import java.time.Instant;
import java.util.List;

@RestController
@RequiredArgsConstructor
public class ParController {
    public static final String PAR_REQUEST_MAPPING = "/as/par";
    public static final String REQUIRED_CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation";
    public static final String REQUIRED_CLIENT_ASSERTION_FORMAT = "[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+~[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+";
    private static final String REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:";
    private final AuthorizationServerProperties.AuthorizationServer asProperties;
    private final ClientAttestationValidator clientAttestationValidator;
    private final AuthorizationRequestValidator authorizationRequestValidator;
    private final SessionRepository sessionRepository;
    private final ObjectMapper objectMapper;

    @PostMapping(path = PAR_REQUEST_MAPPING, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE, params = "request")
    public ResponseEntity<ParResponse> par(@RequestParam(name = "request") String request,
                                           @RequestParam(name = "client_assertion_type") @Pattern(regexp = REQUIRED_CLIENT_ASSERTION_TYPE) String clientAssertionType,
                                           @RequestParam(name = "client_assertion") @Pattern(regexp = REQUIRED_CLIENT_ASSERTION_FORMAT) String clientAssertion) throws ParseException {
        String audience = asProperties.baseUrl() + PAR_REQUEST_MAPPING;
        Pair<SignedJWT, SignedJWT> clientAttestationAndPoP = clientAttestationValidator.validate(clientAssertion, audience);
        JWTClaimsSet requestObjectClaimsSet = authorizationRequestValidator.validate(request, clientAttestationAndPoP.getLeft());

        URI requestUri = URI.create(REQUEST_URI_PREFIX + new State().getValue());
        createSession(requestUri, requestObjectClaimsSet);
        long expiresIn = asProperties.ttl().requestUri().toSeconds();
        return ResponseEntity.status(HttpStatus.CREATED).body(new ParResponse(requestUri, expiresIn));
    }

    @PostMapping(path = PAR_REQUEST_MAPPING, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE, params = "client_id")
    public ResponseEntity<ParResponse> par(@RequestParam(name = "state") String state,
                                           @RequestParam(name = "client_id") String clientId,
                                           @RequestParam(name = "code_challenge") String codeChallenge,
                                           @RequestParam(name = "code_challenge_method") String codeChallengeMethod,
                                           @RequestParam(name = "redirect_uri") String redirectUri,
                                           @RequestParam(name = "authorization_details") String authorizationDetails
    ) throws ParseException, JsonProcessingException {

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        builder.claim("state", state);
        builder.claim("client_id", clientId);
        builder.claim("code_challenge", codeChallenge);
        builder.claim("code_challenge_method", codeChallengeMethod);
        builder.claim("redirect_uri", redirectUri);
        builder.claim("authorization_details", objectMapper.readValue(authorizationDetails, new TypeReference<List<AuthorizationDetails>>() {
        }));
        URI requestUri = URI.create(REQUEST_URI_PREFIX + new State().getValue());
        createSession(requestUri, builder.build());
        long expiresIn = asProperties.ttl().requestUri().toSeconds();
        return ResponseEntity.status(HttpStatus.CREATED).body(new ParResponse(requestUri, expiresIn));
    }

    private void createSession(URI requestUri, JWTClaimsSet requestObjectClaims) throws ParseException {
        sessionRepository.save(Session.builder()
            .requestUri(requestUri)
            .requestUriExpirationTime(Instant.now())
            .requestObjectClaims(requestObjectClaims)
            .build());
    }
}
