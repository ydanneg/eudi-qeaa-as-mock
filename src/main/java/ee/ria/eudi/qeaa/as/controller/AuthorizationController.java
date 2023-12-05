package ee.ria.eudi.qeaa.as.controller;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import ee.ria.eudi.qeaa.as.error.ServiceException;
import ee.ria.eudi.qeaa.as.model.Session;
import ee.ria.eudi.qeaa.as.repository.SessionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

@RestController
@RequiredArgsConstructor
public class AuthorizationController {
    public static final String AUTHORIZE_REQUEST_MAPPING = "/authorize";
    private final SessionRepository sessionRepository;

    @GetMapping(path = AUTHORIZE_REQUEST_MAPPING)
    public ResponseEntity<Void> authorize(@RequestParam(name = "client_id") String clientId,
                                          @RequestParam(name = "request_uri") String requestUri) {
        String authCode = new AuthorizationCode().getValue();
        Session session = updateSession(clientId, requestUri, authCode);

        // TODO: User authentication with PID

        URI redirectUri = UriComponentsBuilder.fromUriString(session.getRedirectUri())
            .queryParam("state", session.getState())
            .queryParam("code", authCode)
            .build().toUri();
        return ResponseEntity.status(HttpStatus.FOUND).location(redirectUri).build();
    }

    private Session updateSession(String clientId, String requestUri, String authCode) {
        Session session = sessionRepository.findByClientIdAndRequestUriAndRequestUriUsed(clientId, requestUri, false)
            .orElseThrow(() -> new ServiceException("Session not found"));
        if (session.isRequestUriExpired()) {
            throw new ServiceException("Authorization request expired");
        }
        session.setAuthorizationCode(authCode);
        session.setRequestUriUsed(true);
        sessionRepository.save(session);
        return session;
    }
}
