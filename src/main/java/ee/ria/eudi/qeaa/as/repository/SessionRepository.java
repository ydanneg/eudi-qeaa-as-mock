package ee.ria.eudi.qeaa.as.repository;

import ee.ria.eudi.qeaa.as.model.Session;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface SessionRepository extends JpaRepository<Session, Long> {

    Optional<Session> findByPresentationRequestState(String state);

    Optional<Session> findByPresentationRequestRequestUriId(String presentationRequestUriId);

    Optional<Session> findByPresentationResponseResponseCode(String presentationResponseCode);

    Optional<Session> findByClientIdAndRequestUriAndRequestUriUsed(String clientId, String requestUri, boolean requestUriUsed);

    Optional<Session> findByClientIdAndAuthorizationCodeAndAuthorizationCodeUsedAndRedirectUri(String clientId, String authorizationCode, boolean authorizationCodeUsed, String redirectUri);
}
