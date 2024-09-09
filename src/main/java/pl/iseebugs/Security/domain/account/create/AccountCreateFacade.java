package pl.iseebugs.Security.domain.account.create;

import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.account.AccountHelper;
import pl.iseebugs.Security.domain.account.EmailNotFoundException;
import pl.iseebugs.Security.domain.account.lifecycle.dto.AppUserDto;
import pl.iseebugs.Security.domain.account.lifecycle.dto.LoginRequest;
import pl.iseebugs.Security.domain.email.EmailFacade;
import pl.iseebugs.Security.domain.email.EmailSender;
import pl.iseebugs.Security.domain.email.EmailType;
import pl.iseebugs.Security.domain.email.InvalidEmailTypeException;
import pl.iseebugs.Security.domain.security.SecurityFacade;
import pl.iseebugs.Security.domain.account.TokenNotFoundException;
import pl.iseebugs.Security.domain.security.projection.AuthReqRespDTO;
import pl.iseebugs.Security.domain.security.projection.LoginTokenDto;
import pl.iseebugs.Security.domain.user.AppUserFacade;
import pl.iseebugs.Security.domain.user.AppUserNotFoundException;
import pl.iseebugs.Security.domain.user.dto.AppUserReadModel;
import pl.iseebugs.Security.domain.user.dto.AppUserWriteModel;


import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
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

    public LoginTokenDto signUp(LoginRequest registrationRequest) throws EmailSender.EmailConflictException, InvalidEmailTypeException, AppUserNotFoundException, TokenNotFoundException {
        String email = registrationRequest.getEmail();
        String password = securityFacade.passwordEncode(registrationRequest.getPassword());
        String roles = "USER";

        validateEmailConflict(email);
        AppUserReadModel created = createAppUser(email, password, roles);
        log.info("Created new user with id: {}, locked: {}, blocked: {}", created.id(), created.locked(), created.enabled());

        String token = getUUID();

        ConfirmationToken confirmationToken = createNewConfirmationToken(token, created.id());
        Date tokenExpiresAt = Date.from(confirmationToken.getExpiresAt().atZone(ZoneId.systemDefault()).toInstant());

        AppUserDto dataToEmail = AppUserDto.builder()
                .firstName(null)
                .email(email).build();

        String link = accountHelper.createUrl("/api/auth/confirm?token=", token);
        emailFacade.sendTemplateEmail(
                EmailType.ACTIVATION,
                dataToEmail,
                link);

        return new LoginTokenDto(token, tokenExpiresAt);
    }

    public void confirmToken(final String token) throws TokenNotFoundException, RegistrationTokenConflictException, AppUserNotFoundException {
        ConfirmationToken confirmationToken = confirmationTokenService.getTokenByToken(token)
                .orElseThrow(TokenNotFoundException::new);

        validateConfirmationToken(confirmationToken);

        confirmationTokenService.setConfirmedAt(token);
        appUserFacade.enableAppUser(confirmationToken.getAppUserId());
    }

    public AuthReqRespDTO refreshConfirmationToken(String email) throws InvalidEmailTypeException, TokenNotFoundException, RegistrationTokenConflictException, AppUserNotFoundException, EmailNotFoundException {
        AuthReqRespDTO responseDTO = new AuthReqRespDTO();
        responseDTO.setEmail(email);

        AppUserReadModel appUserResult = appUserFacade.findByEmail(email);
        responseDTO.setFirstName(appUserResult.firstName());
        responseDTO.setLastName(appUserResult.lastName());

        String token = getUUID();
        responseDTO.setToken(token);

        if (confirmationTokenService.getTokenByUserId(appUserResult.id()).isEmpty()) {
            createNewConfirmationToken(token, appUserResult.id());
            responseDTO.setStatusCode(201);
        } else if (confirmationTokenService.getTokenByUserId(appUserResult.id()).get().getConfirmedAt() != null
                && confirmationTokenService.isConfirmed(appUserResult.id())) {
            log.info("Confirmation token already confirmed.");
            throw new RegistrationTokenConflictException("Confirmation token already confirmed.");
        } else {
            ConfirmationToken confirmationToken = confirmationTokenService.getTokenByUserId(appUserResult.id())
                    .orElseThrow(() -> new TokenNotFoundException("Confirmation token not found."));

            confirmationToken.setCreatedAt(LocalDateTime.now());
            confirmationToken.setExpiresAt(LocalDateTime.now().plusMinutes(CONFIRMATION_ACCOUNT_TOKEN_EXPIRATION_TIME));
            confirmationToken.setToken(token);
            confirmationTokenService.saveConfirmationToken(confirmationToken);
            responseDTO.setStatusCode(204);
        }

        responseDTO.setMessage("Generated new confirmation token.");
        responseDTO.setExpirationTime("15 minutes");

        String link = accountHelper.createUrl("/api/auth/confirm?token=", token);

        emailFacade.sendTemplateEmail(EmailType.ACTIVATION, responseDTO, link);

        return responseDTO;
    }

    private static void validateConfirmationToken(final ConfirmationToken confirmationToken) throws RegistrationTokenConflictException {
        if (confirmationToken.getConfirmedAt() != null) {
            log.info("Confirmation token already confirmed.");
            throw new RegistrationTokenConflictException();
        }

        LocalDateTime expiredAt = confirmationToken.getExpiresAt();

        if (expiredAt.isBefore(LocalDateTime.now())) {
            log.info("Token expired.");
            throw new CredentialsExpiredException("Token expired.");
        }
    }

    private static String getUUID() {
        return UUID.randomUUID().toString();
    }

    private ConfirmationToken createNewConfirmationToken(final String token, final Long userId) throws TokenNotFoundException {
        ConfirmationToken confirmationToken = new ConfirmationToken(
                token,
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(CONFIRMATION_ACCOUNT_TOKEN_EXPIRATION_TIME),
                userId
        );
        confirmationTokenService.saveConfirmationToken(confirmationToken);
        return confirmationTokenService.getTokenByToken(token).orElseThrow(TokenNotFoundException::new);
    }

    private AppUserReadModel createAppUser(final String email, final String password, final String roles) throws AppUserNotFoundException {
        AppUserWriteModel userToCreate = AppUserWriteModel.builder()
                .email(email)
                .password(password)
                .role(roles)
                .locked(false)
                .enabled(false)
                .build();

        return appUserFacade.create(userToCreate);
    }

    private void validateEmailConflict(final String email) throws EmailSender.EmailConflictException {
        if (appUserFacade.existsByEmail(email)) {
            throw new EmailSender.EmailConflictException();
        }
    }

    public ConfirmationToken getTokenByUserId(Long userId) throws TokenNotFoundException {
        return confirmationTokenService.getTokenByUserId(userId)
                .orElseThrow(() -> new TokenNotFoundException("Confirmation token not found."));
    }
}
