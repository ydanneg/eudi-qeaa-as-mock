package ee.ria.eudi.qeaa.as.validation;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPIssuer;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DefaultDPoPSingleUseChecker;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.util.singleuse.AlreadyUsedException;
import ee.ria.eudi.qeaa.as.error.ServiceException;

import java.time.Clock;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static ee.ria.eudi.qeaa.as.error.ErrorCode.INVALID_DPOP_PROOF;

public class DPoPClaimsVerifier extends DefaultJWTClaimsVerifier<SecurityContext> {
    private final long expiryTimeSeconds;
    private final long maxClockSkewSeconds;
    private final DefaultDPoPSingleUseChecker singleUseChecker;
    private final DPoPIssuer dPoPIssuer;
    private final Clock systemClock;

    public DPoPClaimsVerifier(String httpUri,
                              String httpMethod,
                              long expiryTimeSeconds,
                              long maxClockSkewSeconds,
                              DPoPIssuer dPoPIssuer,
                              DefaultDPoPSingleUseChecker singleUseChecker,
                              Clock systemClock) {
        super(new JWTClaimsSet.Builder()
                .claim("htu", httpUri)
                .claim("htm", httpMethod)
                .build(),
            Set.of(JWTClaimNames.ISSUED_AT, JWTClaimNames.JWT_ID));
        this.expiryTimeSeconds = expiryTimeSeconds;
        this.maxClockSkewSeconds = maxClockSkewSeconds;
        this.singleUseChecker = singleUseChecker;
        this.dPoPIssuer = dPoPIssuer;
        this.systemClock = systemClock;
    }

    @Override
    public void verify(JWTClaimsSet claimsSet, SecurityContext context) throws BadJWTException {
        super.verify(claimsSet, context);

        Date currentTime = Date.from(systemClock.instant());
        if (!DateUtils.isAfter(claimsSet.getIssueTime(), currentTime, expiryTimeSeconds + maxClockSkewSeconds)) {
            throw new ServiceException(INVALID_DPOP_PROOF, "DPoP expired");
        }
        if (!DateUtils.isBefore(claimsSet.getIssueTime(), currentTime, maxClockSkewSeconds)) {
            throw new ServiceException(INVALID_DPOP_PROOF, "DPoP not yet valid");
        }
        if (singleUseChecker != null) {
            JWTID jti = new JWTID(claimsSet.getJWTID());
            try {
                singleUseChecker.markAsUsed(Map.entry(Objects.requireNonNull(dPoPIssuer), jti));
            } catch (AlreadyUsedException e) {
                throw new ServiceException(INVALID_DPOP_PROOF, "DPoP has already been used");
            }
        }
    }
}
