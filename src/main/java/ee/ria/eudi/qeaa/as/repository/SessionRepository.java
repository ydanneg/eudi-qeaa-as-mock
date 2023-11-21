package ee.ria.eudi.qeaa.as.repository;

import ee.ria.eudi.qeaa.as.model.Session;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SessionRepository extends JpaRepository<Session, Long> {

    Session findByClientIdAndRequestUri(String clientId, String requestUri);
}
