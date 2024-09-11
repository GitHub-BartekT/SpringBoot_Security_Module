package pl.iseebugs.Security.domain.account.create;

import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.ApiResponse;
import pl.iseebugs.Security.domain.account.AccountHelper;
import pl.iseebugs.Security.domain.account.EmailNotFoundException;
import pl.iseebugs.Security.domain.account.TokenNotFoundException;
import pl.iseebugs.Security.domain.account.lifecycle.dto.LoginRequest;
import pl.iseebugs.Security.domain.email.EmailSender;
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

import static pl.iseebugs.Security.domain.account.AccountHelper.getUUID;

@Log4j2
@Service
public class AccountCreateFacade {

    private static final Long CONFIRMATION_ACCOUNT_TOKEN_EXPIRATION_TIME = 15L;
    private static final String USER_ROLE = "USER";
    private static final String TOKEN_CONFIRMATION_ENDPOINT = "/api/auth/create/confirm?token=";

    SecurityFacade securityFacade;
    AppUserFacade appUserFacade;
    ConfirmationTokenService confirmationTokenService;
    AccountHelper accountHelper;
    CreateAccountValidator createAccountValidator;

    AccountCreateFacade(SecurityFacade securityFacade,
                        AppUserFacade appUserFacade,
                        ConfirmationTokenService confirmationTokenService,
                        AccountHelper accountHelper,
                        CreateAccountValidator createAccountValidator) {
        this.securityFacade = securityFacade;
        this.appUserFacade = appUserFacade;
        this.confirmationTokenService = confirmationTokenService;
        this.accountHelper = accountHelper;
        this.createAccountValidator = createAccountValidator;
    }

    public ApiResponse<LoginTokenDto> signUp(LoginRequest registrationRequest) throws EmailSender.EmailConflictException, InvalidEmailTypeException, AppUserNotFoundException, TokenNotFoundException {
        String email = registrationRequest.getEmail();
        String password = securityFacade.passwordEncode(registrationRequest.getPassword());

        createAccountValidator.validateEmailConflict(email);
        AppUserReadModel createdUser = createAppUser(email, password);
        String token = createNewConfirmationToken(createdUser.id());
        sendConfirmationEmail(email, token);

        return buildSignUpSuccessResponse(token, calculateTokenExpiration(token));
    }

    private ApiResponse<LoginTokenDto> buildSignUpSuccessResponse(final String token, Date tokenExpiresAt) throws TokenNotFoundException {
        return ApiResponse.<LoginTokenDto>builder()
                .statusCode(HttpStatus.OK.value())
                .message("Successfully signed up.")
                .data(new LoginTokenDto(token, tokenExpiresAt))
                .build();
    }

    public ApiResponse confirmToken(final String token) throws TokenNotFoundException, RegistrationTokenConflictException, AppUserNotFoundException {
        ConfirmationToken confirmationToken = confirmationTokenService.getTokenByToken(token)
                .orElseThrow(TokenNotFoundException::new);

        createAccountValidator.validateConfirmationToken(confirmationToken);

        confirmationTokenService.setConfirmedAt(token);
        appUserFacade.enableAppUser(confirmationToken.getAppUserId());
        return buildErrorResponse(HttpStatus.OK.value(), "Account successfully confirmed");
    }

    private static ApiResponse<LoginTokenDto> buildErrorResponse(int statusCode, String message) {
        return ApiResponse.<LoginTokenDto>builder()
                .statusCode(statusCode)
                .message(message)
                .build();
    }


    public ApiResponse<LoginTokenDto> refreshConfirmationToken(final String email) throws InvalidEmailTypeException, TokenNotFoundException, RegistrationTokenConflictException, AppUserNotFoundException, EmailNotFoundException {
        ApiResponse<LoginTokenDto> response = new ApiResponse<>();

        AppUserReadModel appUserResult = appUserFacade.findByEmail(email);
        Long userId = appUserResult.id();
        String token = null;

        Optional<ConfirmationToken> toCheck = confirmationTokenService.getTokenByUserId(userId);
        ConfirmationToken confirmationToken;
        if (toCheck.isEmpty()) {
            token = createNewConfirmationToken(userId);

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
            token = getUUID();
            confirmationToken.setToken(token);
            confirmationTokenService.saveConfirmationToken(confirmationToken);

            response.setStatusCode(204);
            response.setMessage("Successfully generated new confirmation token.");
        }

        sendConfirmationEmail(email, token);

        LoginTokenDto loginTokenDto = new LoginTokenDto(token, calculateTokenExpiration(token));
        response.setData(loginTokenDto);
        return response;
    }

    public ConfirmationToken getTokenByUserId(Long userId) throws TokenNotFoundException {
        return confirmationTokenService.getTokenByUserId(userId)
                .orElseThrow(() -> new TokenNotFoundException("Confirmation token not found."));
    }

    private String createNewConfirmationToken(final Long userId) {
        String token = getUUID();
        ConfirmationToken confirmationToken = new ConfirmationToken(
                token,
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(CONFIRMATION_ACCOUNT_TOKEN_EXPIRATION_TIME),
                userId
        );
        confirmationTokenService.saveConfirmationToken(confirmationToken);
        return token;
    }

    private Date calculateTokenExpiration(String token) throws TokenNotFoundException {
        ConfirmationToken confirmationToken = confirmationTokenService.getTokenByToken(token)
                .orElseThrow(() -> new TokenNotFoundException("Token not found."));
        return Date.from(confirmationToken.getExpiresAt().atZone(ZoneId.systemDefault()).toInstant());
    }

    private AppUserReadModel createAppUser(final String email, final String password) throws AppUserNotFoundException {
        AppUserWriteModel userToCreate = AppUserWriteModel.builder()
                .email(email)
                .password(password)
                .role(USER_ROLE)
                .locked(false)
                .enabled(false)
                .build();
        return appUserFacade.create(userToCreate);
    }

    private void sendConfirmationEmail(String email, String token) throws InvalidEmailTypeException {
        accountHelper.sendMailWithConfirmationToken(email, TOKEN_CONFIRMATION_ENDPOINT, token);
    }
}
