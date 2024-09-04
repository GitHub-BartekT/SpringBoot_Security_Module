package pl.iseebugs.Security.domain.account.delete;

import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.account.AccountHelper;
import pl.iseebugs.Security.domain.account.EmailNotFoundException;
import pl.iseebugs.Security.domain.email.EmailFacade;
import pl.iseebugs.Security.domain.email.EmailType;
import pl.iseebugs.Security.domain.security.SecurityFacade;
import pl.iseebugs.Security.domain.account.TokenNotFoundException;
import pl.iseebugs.Security.domain.security.projection.AuthReqRespDTO;
import pl.iseebugs.Security.domain.user.AppUserFacade;
import pl.iseebugs.Security.domain.user.AppUserNotFoundException;
import pl.iseebugs.Security.domain.user.dto.AppUserReadModel;
import pl.iseebugs.Security.domain.user.dto.AppUserWriteModel;

import java.time.LocalDateTime;
import java.util.UUID;

@Log4j2
@Service
@AllArgsConstructor
public class AccountDeleteFacade {

    private static Long DELETE_ACCOUNT_TOKEN_EXPIRATION_TIME = 1440L;

    private final DeleteTokenService deleteTokenService;
    private final AppUserFacade appUserFacade;
    private final SecurityFacade securityFacade;
    private final EmailFacade emailFacade;
    private final AccountHelper helper;

    public AuthReqRespDTO deleteUser(String accessToken) throws Exception {
        securityFacade.isAccessToken(accessToken);
        securityFacade.isTokenExpired(accessToken);

        String userEmail = securityFacade.extractUsername(accessToken);
        AppUserReadModel user = appUserFacade.findByEmail(userEmail);

        AuthReqRespDTO responseDTO = new AuthReqRespDTO();
        responseDTO.setFirstName(user.firstName());
        responseDTO.setEmail(user.email());

        String token = UUID.randomUUID().toString();

        DeleteToken deleteToken = deleteTokenService.getTokenByUserId(user.id()).isPresent() ?
                deleteTokenService.getTokenByUserId(user.id()).orElseThrow(TokenNotFoundException::new) :
                new DeleteToken();

        deleteToken.setToken(token);
        deleteToken.setCreatedAt(LocalDateTime.now());
        deleteToken.setExpiresAt(LocalDateTime.now().plusMinutes(DELETE_ACCOUNT_TOKEN_EXPIRATION_TIME));
        deleteToken.setAppUserId(user.id());

        deleteTokenService.saveDeleteToken(deleteToken);
        responseDTO.setToken(token);

        responseDTO.setMessage("Delete confirmation mail created successfully.");
        responseDTO.setExpirationTime("24 hours");
        responseDTO.setStatusCode(201);

        String link = helper.createUrl("/api/auth/delete-confirm?token=", token);

        emailFacade.sendTemplateEmail(
                EmailType.DELETE,
                responseDTO,
                link);

        return responseDTO;
    }

    public AuthReqRespDTO confirmDeleteToken(final String token) throws TokenNotFoundException, AppUserNotFoundException, EmailNotFoundException {
        DeleteToken deleteToken;
        deleteToken = deleteTokenService.getToken(token)
                .orElseThrow(TokenNotFoundException::new);

        AuthReqRespDTO response = new AuthReqRespDTO();
        LocalDateTime expiredAt = deleteToken.getExpiresAt();

        if (expiredAt.isBefore(LocalDateTime.now())) {
            log.info("Token expired.");
            throw new CredentialsExpiredException("Token expired.");
        }

        deleteTokenService.setConfirmedAt(token);

        anonymization(deleteToken.getAppUserId());

        response.setStatusCode(204);
        response.setMessage("User account successfully deleted.");
        return response;
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
