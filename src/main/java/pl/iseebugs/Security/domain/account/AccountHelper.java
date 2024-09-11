package pl.iseebugs.Security.domain.account;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;
import pl.iseebugs.Security.domain.account.lifecycle.dto.AppUserDto;
import pl.iseebugs.Security.domain.email.EmailFacade;
import pl.iseebugs.Security.domain.email.EmailType;
import pl.iseebugs.Security.domain.email.InvalidEmailTypeException;
import pl.iseebugs.Security.domain.security.AuthorizationProperties;
import pl.iseebugs.Security.domain.security.SecurityFacade;
import pl.iseebugs.Security.domain.user.AppUserFacade;
import pl.iseebugs.Security.domain.user.dto.AppUserReadModel;

import java.util.UUID;

@Component
public class AccountHelper {

    public static int CONFIRMATION_ACCOUNT_TOKEN_EXPIRATION_TIME;
    public static int DELETE_ACCOUNT_TOKEN_EXPIRATION_TIME;

    private final AppProperties appProperties;
    private final EmailFacade emailFacade;
    private final SecurityFacade securityFacade;
    private final AppUserFacade appUserFacade;

    AccountHelper(AppProperties appProperties,
    EmailFacade emailFacade,
    SecurityFacade securityFacade,
    AppUserFacade appUserFacade,
    AuthorizationProperties authorizationProperties ){
        this.appProperties = appProperties;
        this.emailFacade = emailFacade;
        this.securityFacade = securityFacade;
        this.appUserFacade = appUserFacade;
        CONFIRMATION_ACCOUNT_TOKEN_EXPIRATION_TIME = authorizationProperties.getExpirationConfirmationTokenTime();
        DELETE_ACCOUNT_TOKEN_EXPIRATION_TIME = authorizationProperties.getExpirationDeleteTokenTime();
    }

    public void sendMailWithConfirmationToken(final String email, final String endpoint, final String token) throws InvalidEmailTypeException {
        sendMailWithToken(EmailType.ACTIVATION, email, endpoint, token);
    }

    public void sendMailWithDeleteToken(final String email, final String endpoint, final String token) throws InvalidEmailTypeException {
        sendMailWithToken(EmailType.DELETE, email, endpoint, token);
    }

    private void sendMailWithToken(EmailType emailType, final String email, final String endpoint, final String token) throws InvalidEmailTypeException {
        AppUserDto dataToEmail = AppUserDto.builder()
                .firstName(null)
                .email(email).build();

        String link = createUrl(endpoint, token);
        emailFacade.sendTemplateEmail(emailType, dataToEmail, link);
    }

    public String createUrl(final String endpoint, final String token) {
        return appProperties.uri() + ":" +
                appProperties.port() +
                endpoint +
                token;
    }

    public static String getUUID() {
        return UUID.randomUUID().toString();
    }

    public AppUserReadModel getAppUserReadModelFromToken(final String accessToken) throws EmailNotFoundException {
        String userEmail = securityFacade.extractUsername(accessToken);
        return appUserFacade.findByEmail(userEmail);
    }
}
