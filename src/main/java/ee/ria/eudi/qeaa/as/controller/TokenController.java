package ee.ria.eudi.qeaa.as.controller;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.JWTID;
import ee.ria.eudi.qeaa.as.configuration.properties.AuthorizationServerProperties;
import ee.ria.eudi.qeaa.as.error.ServiceException;
import ee.ria.eudi.qeaa.as.model.AuthorizationDetails;
import ee.ria.eudi.qeaa.as.model.CredentialNonce;
import ee.ria.eudi.qeaa.as.model.Session;
import ee.ria.eudi.qeaa.as.model.TokenResponse;
import ee.ria.eudi.qeaa.as.repository.SessionRepository;
import ee.ria.eudi.qeaa.as.service.CredentialNonceService;
import ee.ria.eudi.qeaa.as.validation.ClientAttestationValidator;
import ee.ria.eudi.qeaa.as.validation.DPoPValidator;
import ee.ria.eudi.qeaa.as.validation.PKCEValidator;
import jakarta.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.text.ParseException;
import java.time.Instant;
import java.util.Map;

@Validated
@RestController
@RequiredArgsConstructor
public class TokenController {
    public static final String REQUIRED_CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation";
    public static final String REQUIRED_CLIENT_ASSERTION_FORMAT = "[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+~[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+";
    public static final String TOKEN_REQUEST_MAPPING = "/token";
    public static final String REQUIRED_GRANT_TYPE = "authorization_code";
    private final AuthorizationServerProperties properties;
    private final ClientAttestationValidator clientAttestationValidator;
    private final PKCEValidator pkceValidator;
    private final DPoPValidator dPoPValidator;
    private final SessionRepository sessionRepository;
    private final ECDSASigner asSigner;
    private final JWSAlgorithm asSigningKeyJwsAlg;
    private final CredentialNonceService credentialNonceService;

    @PostMapping(path = TOKEN_REQUEST_MAPPING)
    public ResponseEntity<TokenResponse> tokenRequest(@RequestHeader("DPoP") String dPoPHeader,
                                                      @RequestParam(name = "client_id") String clientId,
                                                      @RequestParam(name = "grant_type") @Pattern(regexp = REQUIRED_GRANT_TYPE, message = "Invalid grant type") String grantType,
                                                      @RequestParam(name = "code") String authorizationCode,
                                                      @RequestParam(name = "code_verifier") String codeVerifier,
                                                      @RequestParam(name = "client_assertion_type") @Pattern(regexp = REQUIRED_CLIENT_ASSERTION_TYPE) String clientAssertionType,
                                                      @RequestParam(name = "client_assertion") @Pattern(regexp = REQUIRED_CLIENT_ASSERTION_FORMAT) String clientAssertion,
                                                      @RequestParam(name = "redirect_uri") String redirectUri) throws BadJOSEException, ParseException, JOSEException, CertificateNotYetValidException, CertificateExpiredException {
        Session session = updateSession(clientId, authorizationCode, redirectUri);
        pkceValidator.validate(codeVerifier, session);
        String audience = properties.as().baseUrl() + TOKEN_REQUEST_MAPPING;
        clientAttestationValidator.validate(clientAssertion, audience);
        SignedJWT dPoPJwt = dPoPValidator.validate(dPoPHeader, clientId);
        AuthorizationDetails authorizationDetails = session.getAuthorizationDetails().getFirst();
        String credentialIssuerId = authorizationDetails.getLocations().getFirst();
        SignedJWT accessToken = getSenderConstrainedAccessToken(clientId, dPoPJwt, credentialIssuerId);
        CredentialNonce credentialNonce = credentialNonceService.requestNonce(credentialIssuerId, accessToken); // TODO: Request nonce only if nonce endpoint url in issuer metadata
        TokenResponse response = new TokenResponse(accessToken.serialize(),
            "DPoP",
            credentialNonce.cNonce(),
            credentialNonce.cNonceExpiresIn(),
            authorizationDetails);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    private Session updateSession(String clientId, String authorizationCode, String redirectUri) {
        Session session = sessionRepository.findByClientIdAndAuthorizationCodeAndAuthorizationCodeUsedAndRedirectUri(clientId, authorizationCode, false, redirectUri)
            .orElseThrow(() -> new ServiceException("Session not found"));
        session.setAuthorizationCodeUsed(true);
        sessionRepository.save(session);
        return session;
    }

    private SignedJWT getSenderConstrainedAccessToken(String clientId, SignedJWT dPoPJwt, String credentialIssuerId) throws JOSEException {
        JWK dPoPKey = dPoPJwt.getHeader().getJWK();
        SignedJWT accessToken = new SignedJWT(new JWSHeader.Builder(asSigningKeyJwsAlg)
            .type(JOSEObjectType.JWT)
            .build(), getAccessTokenClaims(clientId, credentialIssuerId, dPoPKey));
        accessToken.sign(asSigner);
        return accessToken;
    }

    private JWTClaimsSet getAccessTokenClaims(String clientId, String audience, JWK dPoPKey) throws JOSEException {
        JWTID jti = new JWTID(40);
        long issuedAtClaim = Instant.now().getEpochSecond();
        long expClaim = issuedAtClaim + properties.as().ttl().accessToken().toSeconds();
        return new JWTClaimsSet.Builder()
            .claim(JWTClaimNames.ISSUER, properties.as().baseUrl())
            .claim(JWTClaimNames.SUBJECT, properties.as().subject()) // TODO: From PID authentication flow
            .claim(JWTClaimNames.AUDIENCE, audience)
            .claim(JWTClaimNames.JWT_ID, jti.getValue())
            .claim(JWTClaimNames.ISSUED_AT, issuedAtClaim)
            .claim(JWTClaimNames.EXPIRATION_TIME, expClaim)
            .claim("client_id", clientId)
            .claim("cnf", Map.of("jkt", dPoPKey.computeThumbprint().toString()))
            .build();
    }
}
