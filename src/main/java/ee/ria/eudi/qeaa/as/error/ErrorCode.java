package ee.ria.eudi.qeaa.as.error;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {
    SERVICE_EXCEPTION(500),
    INVALID_REQUEST(400),
    INVALID_GRANT(400);

    private final int httpStatusCode;
}
