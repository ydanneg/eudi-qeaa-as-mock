package ee.ria.eudi.qeaa.as.error;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class ServiceException extends RuntimeException {
    private final ErrorCode errorCode;

    public ServiceException(String message) {
        this(ErrorCode.INVALID_REQUEST, message);
    }

    public ServiceException(Throwable cause) {
        super(cause);
        this.errorCode = ErrorCode.SERVICE_EXCEPTION;
    }

    public ServiceException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }
}
