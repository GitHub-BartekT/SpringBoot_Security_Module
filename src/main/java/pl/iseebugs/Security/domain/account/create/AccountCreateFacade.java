package pl.iseebugs.Security.domain.account.create;

import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.account.AccountHelper;
import pl.iseebugs.Security.domain.email.EmailFacade;
import pl.iseebugs.Security.domain.email.EmailSender;
import pl.iseebugs.Security.domain.email.EmailType;
import pl.iseebugs.Security.domain.email.InvalidEmailTypeException;
import pl.iseebugs.Security.domain.loginandregister.RegistrationTokenConflictException;
import pl.iseebugs.Security.domain.security.SecurityFacade;
import pl.iseebugs.Security.domain.security.TokenNotFoundException;
import pl.iseebugs.Security.domain.security.projection.AuthReqRespDTO;
import pl.iseebugs.Security.domain.user.AppUserFacade;
import pl.iseebugs.Security.domain.user.AppUserNotFoundException;
import pl.iseebugs.Security.domain.user.dto.AppUserReadModel;
import pl.iseebugs.Security.domain.user.dto.AppUserWriteModel;

import java.time.LocalDateTime;
import java.util.UUID;

@Log4j2
@Service
public class AccountCreateFacade {

    private static Long CONFIRMATION_ACCOUNT_TOKEN_EXPIRATION_TIME = 15L;

    SecurityFacade securityFacade;
    AppUserFacade appUserFacade;
    ConfirmationTokenService confirmationTokenService;
    AccountHelper accountHelper;
    EmailFacade emailFacade;

    @Autowired
    AccountCreateFacade(SecurityFacade securityFacade,
                        AppUserFacade appUserFacade,
                        ConfirmationTokenService confirmationTokenService,
                        AccountHelper accountHelper,
                        EmailFacade emailFacade) {
        this.securityFacade = securityFacade;
        this.appUserFacade = appUserFacade;
        this.confirmationTokenService = confirmationTokenService;
        this.accountHelper = accountHelper;
        this.emailFacade = emailFacade;
    }

    public AuthReqRespDTO signUp(AuthReqRespDTO registrationRequest) throws EmailSender.EmailConflictException, InvalidEmailTypeException, AppUserNotFoundException {
        AuthReqRespDTO responseDTO = new AuthReqRespDTO();

        String firstName = registrationRequest.getFirstName();
        String lastName = registrationRequest.getLastName();
        String email = registrationRequest.getEmail();
        String password = securityFacade.passwordEncode(registrationRequest.getPassword());
        String roles = "USER";

        if (appUserFacade.existsByEmail(email)) {
            throw new EmailSender.EmailConflictException();
        }

        AppUserWriteModel userToCreate = AppUserWriteModel.builder()
                .firstName(firstName)
                .lastName(lastName)
                .email(email)
                .password(password)
                .role(roles)
                .locked(false)
                .enabled(false)
                .build();

        AppUserReadModel created = appUserFacade.create(userToCreate);
        log.info("Created new user with id: {}, locked: {}, blocked: {}", created.id(), created.locked(), created.enabled());
        String token = UUID.randomUUID().toString();

        ConfirmationToken confirmationToken = new ConfirmationToken(
                token,
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(CONFIRMATION_ACCOUNT_TOKEN_EXPIRATION_TIME),
                created.id()
        );

        confirmationTokenService.saveConfirmationToken(confirmationToken);
        responseDTO.setToken(token);

        if (created.id() != null) {
            responseDTO.setMessage("User created successfully.");
            responseDTO.setExpirationTime("15 minutes");
            responseDTO.setStatusCode(201);

            String link = accountHelper.createUrl("/api/auth/confirm?token=", token);

            emailFacade.sendTemplateEmail(
                    EmailType.ACTIVATION,
                    registrationRequest,
                    link);
        }
        return responseDTO;
    }

    public AuthReqRespDTO confirmToken(final String token) throws TokenNotFoundException, RegistrationTokenConflictException, AppUserNotFoundException {
        ConfirmationToken confirmationToken;
        confirmationToken = confirmationTokenService.getTokenByToken(token)
                .orElseThrow(TokenNotFoundException::new);

        if (confirmationToken.getConfirmedAt() != null) {
            log.info("Confirmation token already confirmed.");
            throw new RegistrationTokenConflictException();
        }

        AuthReqRespDTO response = new AuthReqRespDTO();
        LocalDateTime expiredAt = confirmationToken.getExpiresAt();

        if (expiredAt.isBefore(LocalDateTime.now())) {
            log.info("Token expired.");
            throw new CredentialsExpiredException("Token expired.");
        }

        confirmationTokenService.setConfirmedAt(token);
        appUserFacade.enableAppUser(confirmationToken.getAppUserId());
        response.setStatusCode(200);
        response.setMessage("User confirmed.");
        return response;
    }
}
