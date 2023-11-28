package ee.ria.eudi.qeaa.as.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import ee.ria.eudi.qeaa.as.error.ServiceException;
import lombok.experimental.UtilityClass;

@UtilityClass
public class JwtUtil {

    public JWSVerifier getJwsVerifier(JWK jwk) throws JOSEException {
        if (jwk.getKeyType() == KeyType.RSA) {
            return new RSASSAVerifier(jwk.toRSAKey());
        } else if (jwk.getKeyType() == KeyType.EC) {
            return new ECDSAVerifier(jwk.toECKey());
        } else {
            throw new ServiceException("Unsupported key type: " + jwk.getKeyType());
        }
    }
}
