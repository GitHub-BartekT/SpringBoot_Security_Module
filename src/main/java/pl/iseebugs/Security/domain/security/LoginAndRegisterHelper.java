package pl.iseebugs.Security.domain.security;

import lombok.extern.java.Log;
import org.springframework.stereotype.Component;
import pl.iseebugs.Security.domain.loginandregister.RegistrationTokenConflictException;

@Log
@Component
class LoginAndRegisterHelper {
    private final AppProperties appProperties;
    private final JWTUtils jwtUtils;

    LoginAndRegisterHelper(final AppProperties appProperties, final JWTUtils jwtUtils) {
        this.appProperties = appProperties;
        this.jwtUtils = jwtUtils;
    }

    String createUrl(final String endpoint, final String token) {
        return appProperties.uri() + ":" +
                appProperties.port() +
                endpoint +
                token;
    }

    void validateIsTokenAccess(final String token) throws RegistrationTokenConflictException.BadTokenTypeException {
        if (jwtUtils.isAccessToken(token)) {
            return;
        }
        log.info("The provided token is not an access token.");
        throw new RegistrationTokenConflictException.BadTokenTypeException();
    }

    void validateIsTokenRefresh(final String token) throws RegistrationTokenConflictException.BadTokenTypeException {
        if (jwtUtils.isRefreshToken(token)) {
            return;
        }
        log.info("The provided token is not a refresh token.");
        throw new RegistrationTokenConflictException.BadTokenTypeException();
    }
}
