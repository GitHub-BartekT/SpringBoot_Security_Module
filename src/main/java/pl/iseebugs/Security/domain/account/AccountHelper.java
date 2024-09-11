package pl.iseebugs.Security.domain.account;

import org.springframework.stereotype.Component;
import pl.iseebugs.Security.domain.account.lifecycle.dto.AppUserDto;
import pl.iseebugs.Security.domain.email.EmailFacade;
import pl.iseebugs.Security.domain.email.EmailType;
import pl.iseebugs.Security.domain.email.InvalidEmailTypeException;

import java.util.UUID;

@Component
public class AccountHelper {

    private final AppProperties appProperties;
    private final EmailFacade emailFacade;

    AccountHelper(final AppProperties appProperties, final EmailFacade emailFacade) {
        this.appProperties = appProperties;
        this.emailFacade = emailFacade;
    }

    public void sendMailWithConfirmationToken(final String email, final String endpoint, final String token) throws InvalidEmailTypeException {
        AppUserDto dataToEmail = AppUserDto.builder()
                .firstName(null)
                .email(email).build();

        String link = createUrl(endpoint, token);
        emailFacade.sendTemplateEmail(EmailType.ACTIVATION, dataToEmail, link);
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
}
