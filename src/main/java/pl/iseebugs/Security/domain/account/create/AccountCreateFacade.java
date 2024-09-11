package pl.iseebugs.Security.domain.account.create;

import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.ApiResponse;
import pl.iseebugs.Security.domain.account.AccountHelper;
import pl.iseebugs.Security.domain.account.EmailNotFoundException;
import pl.iseebugs.Security.domain.account.TokenNotFoundException;
import pl.iseebugs.Security.domain.account.lifecycle.dto.AppUserDto;
import pl.iseebugs.Security.domain.account.lifecycle.dto.LoginRequest;
import pl.iseebugs.Security.domain.email.EmailFacade;
import pl.iseebugs.Security.domain.email.EmailSender;
import pl.iseebugs.Security.domain.email.EmailType;
import pl.iseebugs.Security.domain.email.InvalidEmailTypeException;
import pl.iseebugs.Security.domain.security.SecurityFacade;
import pl.iseebugs.Security.domain.security.projection.LoginTokenDto;
import pl.iseebugs.Security.domain.user.AppUserFacade;
import pl.iseebugs.Security.domain.user.AppUserNotFoundException;
import pl.iseebugs.Security.domain.user.dto.AppUserReadModel;
import pl.iseebugs.Security.domain.user.dto.AppUserWriteModel;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Log4j2
@Service
public class AccountCreateFacade {

    private static final Long CONFIRMATION_ACCOUNT_TOKEN_EXPIRATION_TIME = 15L;

    SecurityFacade securityFacade;
    AppUserFacade appUserFacade;
    ConfirmationTokenService confirmationTokenService;
    AccountHelper accountHelper;
    EmailFacade emailFacade;
    CreateAccountValidator createAccountValidator;

    AccountCreateFacade(SecurityFacade securityFacade,
                        AppUserFacade appUserFacade,
                        ConfirmationTokenService confirmationTokenService,
                        AccountHelper accountHelper,
                        EmailFacade emailFacade,
                        CreateAccountValidator createAccountValidator) {
        this.securityFacade = securityFacade;
        this.appUserFacade = appUserFacade;
        this.confirmationTokenService = confirmationTokenService;
        this.accountHelper = accountHelper;
        this.emailFacade = emailFacade;
        this.createAccountValidator = createAccountValidator;
    }

    public ApiResponse<LoginTokenDto> signUp(LoginRequest registrationRequest) throws EmailSender.EmailConflictException, InvalidEmailTypeException, AppUserNotFoundException, TokenNotFoundException {
        String email = registrationRequest.getEmail();
        String password = securityFacade.passwordEncode(registrationRequest.getPassword());
        String roles = "USER";

        createAccountValidator.validateEmailConflict(email);
        AppUserReadModel createdUser = createAppUser(email, password, roles);
        log.info("Created new user with id: {}, locked: {}, blocked: {}", createdUser.id(), createdUser.locked(), createdUser.enabled());

        String token = getUUID();

        ConfirmationToken confirmationToken = createNewConfirmationToken(token, createdUser.id());
        Date tokenExpiresAt = Date.from(confirmationToken.getExpiresAt().atZone(ZoneId.systemDefault()).toInstant());

        sendMailWithConfirmationToken(email, token);
        LoginTokenDto loginTokenDto = new LoginTokenDto(token, tokenExpiresAt);
        return ApiResponse.<LoginTokenDto>builder()
                .statusCode(HttpStatus.OK.value())
                .message("Successfully signed up.")
                .data(loginTokenDto)
                .build();
    }

    public ApiResponse confirmToken(final String token) throws TokenNotFoundException, RegistrationTokenConflictException, AppUserNotFoundException {
        ConfirmationToken confirmationToken = confirmationTokenService.getTokenByToken(token)
                .orElseThrow(TokenNotFoundException::new);

        createAccountValidator.validateConfirmationToken(confirmationToken);

        confirmationTokenService.setConfirmedAt(token);
        appUserFacade.enableAppUser(confirmationToken.getAppUserId());
        return ApiResponse.<LoginTokenDto>builder()
                .statusCode(HttpStatus.OK.value())
                .message("Account successfully confirmed")
                .build();
    }

    public ApiResponse<LoginTokenDto> refreshConfirmationToken(final String email) throws InvalidEmailTypeException, TokenNotFoundException, RegistrationTokenConflictException, AppUserNotFoundException, EmailNotFoundException {
        ApiResponse<LoginTokenDto> response = new ApiResponse<>();

        AppUserReadModel appUserResult = appUserFacade.findByEmail(email);
        Long userId = appUserResult.id();
        String token = getUUID();

        Optional<ConfirmationToken> toCheck = confirmationTokenService.getTokenByUserId(userId);
        ConfirmationToken confirmationToken = null;
        if (toCheck.isEmpty()) {
            confirmationToken = createNewConfirmationToken(token, userId);
            response.setStatusCode(201);
            response.setMessage("Successfully generated new confirmation token.");
        } else if (toCheck.get().getConfirmedAt() != null
                && confirmationTokenService.isConfirmed(appUserResult.id())) {
            response.setStatusCode(401);
            response.setMessage("Account already confirmed.");
        } else {
            confirmationToken = confirmationTokenService.getTokenByUserId(appUserResult.id())
                    .orElseThrow(() -> new TokenNotFoundException("Confirmation token not found."));
            confirmationToken.setCreatedAt(LocalDateTime.now());
            confirmationToken.setExpiresAt(LocalDateTime.now().plusMinutes(CONFIRMATION_ACCOUNT_TOKEN_EXPIRATION_TIME));
            confirmationToken.setToken(token);
            confirmationTokenService.saveConfirmationToken(confirmationToken);
            response.setStatusCode(204);
            response.setMessage("Successfully generated new confirmation token.");
        }

        sendMailWithConfirmationToken(email, token);

        Date tokenExpiresAt = Date.from(confirmationToken.getExpiresAt().atZone(ZoneId.systemDefault()).toInstant());
        LoginTokenDto loginTokenDto = new LoginTokenDto(token, tokenExpiresAt);
        response.setData(loginTokenDto);
        return response;
    }

    private void sendMailWithConfirmationToken(final String email, final String token) throws InvalidEmailTypeException {
        AppUserDto dataToEmail = AppUserDto.builder()
                .firstName(null)
                .email(email).build();

        String link = accountHelper.createUrl("/api/auth/confirm?token=", token);
        emailFacade.sendTemplateEmail(EmailType.ACTIVATION, dataToEmail, link);
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

    public ConfirmationToken getTokenByUserId(Long userId) throws TokenNotFoundException {
        return confirmationTokenService.getTokenByUserId(userId)
                .orElseThrow(() -> new TokenNotFoundException("Confirmation token not found."));
    }
}
