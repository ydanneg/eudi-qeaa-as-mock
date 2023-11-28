package ee.ria.eudi.qeaa.as.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;

import java.security.Key;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Set;

@RequiredArgsConstructor
public class ClientAttestationKeySelector implements JWSKeySelector<SecurityContext> {
    private final SignedJWT clientAttestation;
    private final Set<JWSAlgorithm> acceptedJWSAlgorithms;

    @Override
    public List<? extends Key> selectJWSKeys(JWSHeader header, SecurityContext context) throws KeySourceException {
        JWSAlgorithm alg = header.getAlgorithm();
        if (!acceptedJWSAlgorithms.contains(alg)) {
            throw new KeySourceException("JWS header algorithm not accepted: " + alg);
        }
        String keyID = header.getKeyID();
        if (keyID == null) {
            throw new KeySourceException("JWS header key ID (kid) not specified");
        }
        JWK jwk = getCnfJwk();
        if (!keyID.equals(getKeyThumbprint(jwk))) {
            throw new KeySourceException("JWS header kid / jwk kid mismatch: kid=" + keyID + " jwk.kid=" + jwk.getKeyID());
        }
        if (JWSAlgorithm.Family.RSA.contains(alg) && jwk instanceof RSAKey rsaKey) {
            try {
                return List.of(rsaKey.toRSAPublicKey());
            } catch (JOSEException e) {
                throw new KeySourceException("Invalid RSA JWK: " + e.getMessage(), e);
            }
        } else if (JWSAlgorithm.Family.EC.contains(alg) && jwk instanceof ECKey ecKey) {
            try {
                return List.of(ecKey.toECPublicKey());
            } catch (JOSEException e) {
                throw new KeySourceException("Invalid EC JWK: " + e.getMessage(), e);
            }
        } else {
            throw new KeySourceException("JWS header alg / jwk mismatch: alg=" + alg + " jwk.kty=" + jwk.getKeyType());
        }

    }

    @SneakyThrows
    private static String getKeyThumbprint(JWK jwk) {
        return jwk.computeThumbprint().toString();
    }

    private JWK getCnfJwk() throws KeySourceException {
        try {
            JWTClaimsSet clientAttestationClaims = clientAttestation.getJWTClaimsSet();
            Map<String, Object> cnfClaim = clientAttestationClaims.getJSONObjectClaim("cnf");
            Map<String, Object> jwkClaim = JSONObjectUtils.getJSONObject(cnfClaim, "jwk");
            return JWK.parse(jwkClaim);
        } catch (ParseException e) {
            throw new KeySourceException("Invalid Client Attestation cnf/jwk", e);
        }
    }
}
