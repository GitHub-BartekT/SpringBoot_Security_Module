package pl.iseebugs.Security.domain.account.delete;

import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.ApiResponse;
import pl.iseebugs.Security.domain.account.AccountHelper;
import pl.iseebugs.Security.domain.account.ApiResponseFactory;
import pl.iseebugs.Security.domain.account.EmailNotFoundException;
import pl.iseebugs.Security.domain.account.TokenNotFoundException;
import pl.iseebugs.Security.domain.security.projection.LoginTokenDto;
import pl.iseebugs.Security.domain.user.AppUserFacade;
import pl.iseebugs.Security.domain.user.AppUserNotFoundException;
import pl.iseebugs.Security.domain.user.dto.AppUserReadModel;
import pl.iseebugs.Security.domain.user.dto.AppUserWriteModel;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.UUID;

import static pl.iseebugs.Security.domain.account.AccountHelper.DELETE_ACCOUNT_TOKEN_EXPIRATION_TIME;
import static pl.iseebugs.Security.domain.account.AccountHelper.getUUID;

@Log4j2
@Service
@AllArgsConstructor
public class AccountDeleteFacade {

    private static final String DELETE_CONFIRMATION_ENDPOINT = "/api/auth/delete/delete-confirm?token=";

    private final DeleteTokenService deleteTokenService;
    private final AppUserFacade appUserFacade;
    private final AccountHelper accountHelper;

    public ApiResponse<LoginTokenDto> deleteUser(String accessToken) throws Exception {
        AppUserReadModel user = accountHelper.getAppUserReadModelFromToken(accessToken);
        String token = generateDeleteToken(user);

        accountHelper.sendMailWithDeleteToken(user.email(), DELETE_CONFIRMATION_ENDPOINT, token);

        Date tokenExpiresAt = deleteTokenService.calculateTokenExpiration(token);
        LoginTokenDto deleteTokenDto = new LoginTokenDto(token, tokenExpiresAt);
        return ApiResponseFactory.createResponseWithStatus(HttpStatus.CREATED.value(), "Delete confirmation mail created successfully.", deleteTokenDto);
    }

    private String generateDeleteToken(final AppUserReadModel user){
        DeleteToken deleteToken = deleteTokenService.getTokenByUserId(user.id()).orElseGet(DeleteToken::new);

        deleteToken.setToken(getUUID());
        deleteToken.setCreatedAt(LocalDateTime.now());
        deleteToken.setExpiresAt(LocalDateTime.now().plusMinutes(DELETE_ACCOUNT_TOKEN_EXPIRATION_TIME));
        deleteToken.setAppUserId(user.id());

        deleteTokenService.saveDeleteToken(deleteToken);

        return deleteToken.getToken();
    }

    public ApiResponse<Void> confirmDeleteToken(final String token) throws TokenNotFoundException, AppUserNotFoundException, EmailNotFoundException {
        DeleteToken deleteToken = deleteTokenService.getToken(token)
                .orElseThrow(TokenNotFoundException::new);

        LocalDateTime expiredAt = deleteToken.getExpiresAt();

        if (expiredAt.isBefore(LocalDateTime.now())) {
            throw new CredentialsExpiredException("Token expired.");
        }

        deleteTokenService.setConfirmedAt(token);

        anonymization(deleteToken.getAppUserId());

        return ApiResponseFactory.createResponseWithoutData(HttpStatus.NO_CONTENT.value(), "User account successfully deleted.");
    }

    private void anonymization(final Long id) throws AppUserNotFoundException, EmailNotFoundException {
        AppUserReadModel user = appUserFacade.findUserById(id);
        AppUserWriteModel toAnonymization = AppUserWriteModel.builder()
                .id(user.id())
                .role("DELETED")
                .firstName(UUID.randomUUID().toString())
                .lastName(UUID.randomUUID().toString())
                .password(UUID.randomUUID().toString())
                .email(UUID.randomUUID().toString())
                .locked(true)
                .build();
        appUserFacade.update(toAnonymization);
    }
}
