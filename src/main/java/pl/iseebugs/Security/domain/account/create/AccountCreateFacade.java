package pl.iseebugs.Security.domain.account.create;

import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.ApiResponse;
import pl.iseebugs.Security.domain.account.AccountHelper;
import pl.iseebugs.Security.domain.account.ApiResponseFactory;
import pl.iseebugs.Security.domain.account.EmailNotFoundException;
import pl.iseebugs.Security.domain.account.TokenNotFoundException;
import pl.iseebugs.Security.domain.account.lifecycle.dto.LoginRequest;
import pl.iseebugs.Security.domain.email.EmailSender;
import pl.iseebugs.Security.domain.email.InvalidEmailTypeException;
import pl.iseebugs.Security.domain.security.AuthorizationProperties;
import pl.iseebugs.Security.domain.security.SecurityFacade;
import pl.iseebugs.Security.domain.security.projection.LoginTokenDto;
import pl.iseebugs.Security.domain.user.AppUserFacade;
import pl.iseebugs.Security.domain.user.AppUserNotFoundException;
import pl.iseebugs.Security.domain.user.dto.AppUserReadModel;
import pl.iseebugs.Security.domain.user.dto.AppUserWriteModel;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.Optional;

import static pl.iseebugs.Security.domain.account.AccountHelper.CONFIRMATION_ACCOUNT_TOKEN_EXPIRATION_TIME;
import static pl.iseebugs.Security.domain.account.AccountHelper.getUUID;

@Log4j2
@Service
public class AccountCreateFacade {

    private static final String USER_ROLE = "USER";
    private static final String TOKEN_CONFIRMATION_ENDPOINT = "/api/auth/create/confirm?token=";
    private static final int TOKEN_CREATED_STATUS = 201;
    private static final int TOKEN_EXISTS_STATUS = 204;
    private static final int ACCOUNT_ALREADY_CONFIRMED_STATUS = 401;

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
        String token = confirmationTokenService.createNewConfirmationToken(createdUser.id());

        sendConfirmationEmail(email, token);

        Date tokenExpiresAt = confirmationTokenService.calculateTokenExpiration(token);
        LoginTokenDto loginTokenDto = new LoginTokenDto(token, tokenExpiresAt);

        return ApiResponseFactory.createSuccessResponse("Successfully signed up.", loginTokenDto);
    }

    public ApiResponse<Void> confirmToken(final String token) throws TokenNotFoundException, RegistrationTokenConflictException, AppUserNotFoundException {
        ConfirmationToken confirmationToken = confirmationTokenService.getTokenByToken(token)
                .orElseThrow(TokenNotFoundException::new);

        createAccountValidator.validateConfirmationToken(confirmationToken);

        confirmationTokenService.setConfirmedAt(token);
        appUserFacade.enableAppUser(confirmationToken.getAppUserId());
        return ApiResponseFactory.createResponseWithoutData(HttpStatus.OK.value(), "Account successfully confirmed");
    }

    public ApiResponse<LoginTokenDto> refreshConfirmationToken(final String email) throws InvalidEmailTypeException, TokenNotFoundException, RegistrationTokenConflictException, AppUserNotFoundException, EmailNotFoundException {
        AppUserReadModel user = appUserFacade.findByEmail(email);
        Optional<ConfirmationToken> existingToken = confirmationTokenService.getTokenByUserId(user.id());

        if (existingToken.isPresent()) {
            return handleExistingConfirmationToken(existingToken.get(), user);
        } else {
            return generateNewConfirmationToken(user.id(), email);
        }
    }

    private ApiResponse<LoginTokenDto> handleExistingConfirmationToken(ConfirmationToken existingToken, AppUserReadModel user) throws RegistrationTokenConflictException, InvalidEmailTypeException, TokenNotFoundException {
        if (existingToken.getConfirmedAt() != null) {
            return ApiResponseFactory.createResponseWithoutData(ACCOUNT_ALREADY_CONFIRMED_STATUS, "Account already confirmed.");
        }

        String token = refreshConfirmationToken(existingToken);
        sendConfirmationEmail(user.email(), token);
        Date tokenExpiresAt = confirmationTokenService.calculateTokenExpiration(token);
        return ApiResponseFactory.createResponseWithStatus(TOKEN_EXISTS_STATUS, "Successfully generated new confirmation token.", new LoginTokenDto(token, tokenExpiresAt));
    }

    private String refreshConfirmationToken(ConfirmationToken existingToken) {
        String newToken = getUUID();
        existingToken.setToken(newToken);
        existingToken.setCreatedAt(LocalDateTime.now());
        existingToken.setExpiresAt(LocalDateTime.now().plusMinutes(CONFIRMATION_ACCOUNT_TOKEN_EXPIRATION_TIME));
        confirmationTokenService.saveConfirmationToken(existingToken);
        return newToken;
    }

    private ApiResponse<LoginTokenDto> generateNewConfirmationToken(Long userId, String email) throws InvalidEmailTypeException, TokenNotFoundException {
        String token = confirmationTokenService.createNewConfirmationToken(userId);
        sendConfirmationEmail(email, token);
        Date tokenExpiresAt = confirmationTokenService.calculateTokenExpiration(token);
        return ApiResponseFactory.createResponseWithStatus(TOKEN_CREATED_STATUS, "Successfully generated new confirmation token.", new LoginTokenDto(token, tokenExpiresAt));
    }

    public ConfirmationToken getTokenByUserId(Long userId) throws TokenNotFoundException {
        return confirmationTokenService.getTokenByUserId(userId)
                .orElseThrow(() -> new TokenNotFoundException("Confirmation token not found."));
    }

    private AppUserReadModel createAppUser(final String email, final String password) throws AppUserNotFoundException {
        AppUserWriteModel newUser = AppUserWriteModel.builder()
                .email(email)
                .password(password)
                .role(USER_ROLE)
                .locked(false)
                .enabled(false)
                .build();
        return appUserFacade.create(newUser);
    }

    private void sendConfirmationEmail(String email, String token) throws InvalidEmailTypeException {
        accountHelper.sendMailWithConfirmationToken(email, TOKEN_CONFIRMATION_ENDPOINT, token);
    }
}
