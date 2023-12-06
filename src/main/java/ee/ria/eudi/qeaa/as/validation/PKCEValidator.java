package ee.ria.eudi.qeaa.as.validation;

import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import ee.ria.eudi.qeaa.as.error.ErrorCode;
import ee.ria.eudi.qeaa.as.error.ServiceException;
import ee.ria.eudi.qeaa.as.model.Session;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class PKCEValidator {

    public void validate(String codeVerifier, Session session) {
        CodeChallengeMethod codeChallengeMethod = CodeChallengeMethod.parse(session.getCodeChallengeMethod());
        CodeVerifier verifier = new CodeVerifier(codeVerifier);
        String value = CodeChallenge.compute(codeChallengeMethod, verifier).getValue();
        if (!value.equals(session.getCodeChallenge())) {
            throw new ServiceException(ErrorCode.INVALID_GRANT, "Invalid PKCE code verifier");
        }
    }
}
