package pl.iseebugs.Security.domain.account.lifecycle;

import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.account.BadTokenTypeException;
import pl.iseebugs.Security.domain.account.EmailNotFoundException;
import pl.iseebugs.Security.domain.account.TokenNotFoundException;
import pl.iseebugs.Security.domain.account.create.AccountCreateFacade;
import pl.iseebugs.Security.domain.account.create.ConfirmationToken;
import pl.iseebugs.Security.domain.email.EmailFacade;
import pl.iseebugs.Security.domain.email.EmailType;
import pl.iseebugs.Security.domain.email.InvalidEmailTypeException;
import pl.iseebugs.Security.domain.security.SecurityFacade;
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
public class LifecycleAccountFacade {

    private final AppUserFacade appUserFacade;
    private final SecurityFacade securityFacade;
    private final AccountCreateFacade accountCreateFacade;
    private final EmailFacade emailFacade;

    public AuthReqRespDTO signIn(AuthReqRespDTO signingRequest) throws TokenNotFoundException, EmailNotFoundException {
        AuthReqRespDTO response = new AuthReqRespDTO();
        String email = signingRequest.getEmail();
        log.info("user email: " + email);

        var user = appUserFacade.findByEmail(email);

        ConfirmationToken confirmationToken = accountCreateFacade.getTokenByUserId(user.id());

        LocalDateTime expiredAt = confirmationToken.getExpiresAt();

        if (confirmationToken.getConfirmedAt() == null) {
            if (expiredAt.isAfter(LocalDateTime.now())) {
                log.info("Confirmation token not confirmed.");
                throw new BadCredentialsException("Registration not confirmed.");
            } else {
                log.info("Token expired.");
                throw new CredentialsExpiredException("Token expired.");
            }
        }

        securityFacade.authenticateByAuthenticationManager(email, signingRequest.getPassword());

        var jwt = securityFacade.generateAccessToken(user);
        var refreshToken = securityFacade.generateRefreshToken(user);
        response.setStatusCode(200);
        response.setToken(jwt);
        response.setRefreshToken(refreshToken);
        response.setExpirationTime("24Hr");
        response.setMessage("Successfully singed in");
        return response;
    }

    public AuthReqRespDTO refreshToken(String refreshToken) throws Exception {
        log.info("Start refreshing token");
        securityFacade.isRefreshToken(refreshToken);

        String userEmail = securityFacade.extractUsername(refreshToken);
        AppUserReadModel user = appUserFacade.findByEmail(userEmail);

        if (!securityFacade.isTokenValid(refreshToken, userEmail)) {
            log.info("User with email: " + userEmail + " used an expired token.");
            throw new CredentialsExpiredException("Token expired.");
        }

        AuthReqRespDTO response = new AuthReqRespDTO();

        var jwt = securityFacade.generateAccessToken(user);
        response.setStatusCode(200);
        response.setToken(jwt);
        response.setRefreshToken(refreshToken);
        response.setExpirationTime("60 min");
        response.setMessage("Successfully Refreshed Token");

        log.info("User with email: " + userEmail + " refreshed access token.");
        log.info("Response DTO: " + response);
        return response;
    }

    public AuthReqRespDTO resetPasswordAndNotify(String accessToken) throws BadTokenTypeException, InvalidEmailTypeException, AppUserNotFoundException, EmailNotFoundException {
        securityFacade.isAccessToken(accessToken);

        String userEmail = securityFacade.extractUsername(accessToken);
        AppUserReadModel appUserFromDB = appUserFacade.findByEmail(userEmail);

        String newPassword = UUID.randomUUID().toString();
        String encodePassword = securityFacade.passwordEncode(newPassword);

        AppUserWriteModel toUpdate = AppUserWriteModel.builder()
                .id(appUserFromDB.id())
                .password(encodePassword)
                .build();

        AppUserReadModel updated = appUserFacade.update(toUpdate);

        AuthReqRespDTO responseDTO = new AuthReqRespDTO();

        responseDTO.setMessage("Password changed successfully");
        responseDTO.setStatusCode(200);
        responseDTO.setFirstName(updated.firstName());
        responseDTO.setLastName(updated.lastName());
        responseDTO.setEmail(updated.email());

        emailFacade.sendTemplateEmail(
                EmailType.RESET,
                responseDTO,
                newPassword);

        return responseDTO;
    }

}
