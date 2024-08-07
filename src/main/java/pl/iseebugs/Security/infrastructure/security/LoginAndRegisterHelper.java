package pl.iseebugs.Security.infrastructure.security;

import lombok.extern.java.Log;
import org.springframework.stereotype.Component;

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

    void validateIsTokenAccess(final String token) throws BadTokenTypeException {
        if (jwtUtils.isAccessToken(token)) {
            return;
        }
        log.info("The provided token is not an access token.");
        throw new BadTokenTypeException();
    }

    void validateIsTokenRefresh(final String token) throws BadTokenTypeException {
        if (jwtUtils.isRefreshToken(token)) {
            return;
        }
        log.info("The provided token is not a refresh token.");
        throw new BadTokenTypeException();
    }
}
