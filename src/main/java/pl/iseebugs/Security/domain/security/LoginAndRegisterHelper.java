package pl.iseebugs.Security.domain.security;

import lombok.extern.java.Log;
import org.springframework.stereotype.Component;
import pl.iseebugs.Security.domain.account.BadTokenTypeException;

@Log
@Component
class LoginAndRegisterHelper {

    private final JWTUtils jwtUtils;

    LoginAndRegisterHelper(final JWTUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
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
