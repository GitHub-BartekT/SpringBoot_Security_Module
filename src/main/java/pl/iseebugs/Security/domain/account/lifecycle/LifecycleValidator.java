package pl.iseebugs.Security.domain.account.lifecycle;

import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.stereotype.Component;
import pl.iseebugs.Security.domain.account.TokenNotFoundException;
import pl.iseebugs.Security.domain.account.create.AccountCreateFacade;
import pl.iseebugs.Security.domain.account.create.ConfirmationToken;

import java.time.LocalDateTime;

@Log4j2
@Component
@AllArgsConstructor
class LifecycleValidator {

    private final AccountCreateFacade accountCreateFacade;

    void validConfirmationToken(final Long userId) throws TokenNotFoundException {
        ConfirmationToken confirmationToken = accountCreateFacade.getTokenByUserId(userId);

        LocalDateTime expiredAt = confirmationToken.getExpiresAt();

        if (confirmationToken.getConfirmedAt() == null) {
            if (expiredAt.isAfter(LocalDateTime.now())) {
                throw new BadCredentialsException("Registration not confirmed.");
            } else {
                throw new CredentialsExpiredException("Token expired.");
            }
        }
    }
}
