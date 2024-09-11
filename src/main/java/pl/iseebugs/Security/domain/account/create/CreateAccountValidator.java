package pl.iseebugs.Security.domain.account.create;

import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.stereotype.Component;
import pl.iseebugs.Security.domain.email.EmailSender;
import pl.iseebugs.Security.domain.user.AppUserFacade;

import java.time.LocalDateTime;
@Log4j2
@Component
class CreateAccountValidator {

    static AppUserFacade appUserFacade;

    CreateAccountValidator(AppUserFacade appUserFacade){
        this.appUserFacade = appUserFacade;
    }

    void validateConfirmationToken(final ConfirmationToken confirmationToken) throws RegistrationTokenConflictException {
        if (confirmationToken.getConfirmedAt() != null) {
            log.info("Confirmation token already confirmed.");
            throw new RegistrationTokenConflictException();
        }

        LocalDateTime expiredAt = confirmationToken.getExpiresAt();

        validateTokenExpiration(expiredAt);
    }

    void validateEmailConflict(final String email) throws EmailSender.EmailConflictException {
        if (appUserFacade.existsByEmail(email)) {
            throw new EmailSender.EmailConflictException();
        }
    }

    private static void validateTokenExpiration(final LocalDateTime expiredAt) {
        if (expiredAt.isBefore(LocalDateTime.now())) {
            log.info("Token expired.");
            throw new CredentialsExpiredException("Token expired.");
        }
    }
}
