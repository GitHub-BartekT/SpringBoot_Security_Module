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
import pl.iseebugs.Security.domain.account.lifecycle.dto.LoginRequest;
import pl.iseebugs.Security.domain.account.lifecycle.dto.LoginResponse;
import pl.iseebugs.Security.domain.email.EmailFacade;
import pl.iseebugs.Security.domain.email.EmailType;
import pl.iseebugs.Security.domain.email.InvalidEmailTypeException;
import pl.iseebugs.Security.domain.security.SecurityFacade;
import pl.iseebugs.Security.domain.security.projection.AuthReqRespDTO;
import pl.iseebugs.Security.domain.security.projection.LoginTokenDto;
import pl.iseebugs.Security.domain.user.AppUserFacade;
import pl.iseebugs.Security.domain.user.AppUserNotFoundException;
import pl.iseebugs.Security.domain.user.dto.AppUserReadModel;
import pl.iseebugs.Security.domain.user.dto.AppUserWriteModel;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.UUID;

@Log4j2
@Service
@AllArgsConstructor
public class LifecycleAccountFacade {

    private final AppUserFacade appUserFacade;
    private final SecurityFacade securityFacade;
    private final AccountCreateFacade accountCreateFacade;
    private final EmailFacade emailFacade;

    public LoginResponse login(LoginRequest loginRequest) throws TokenNotFoundException, EmailNotFoundException {
        String email = loginRequest.getEmail();
        String password = loginRequest.getPassword();

        var user = appUserFacade.findByEmail(email);

        validConfirmationToken(user.id());

        securityFacade.authenticateByAuthenticationManager(email, password);

        LoginTokenDto accessToken = securityFacade.generateAccessToken(user);
        LoginTokenDto refreshToken = securityFacade.generateRefreshToken(user);
        return LoginResponse.builder()
                .accessToken(accessToken.token())
                .accessTokenExpiresAt(accessToken.expiresAt())
                .refreshToken(refreshToken.token())
                .refreshTokenExpiresAt(refreshToken.expiresAt())
                .build();
    }

    public LoginResponse refreshToken(String refreshToken) throws Exception {
        log.info("Start refreshing token");
        securityFacade.isRefreshToken(refreshToken);

        String userEmail = securityFacade.extractUsername(refreshToken);
        AppUserReadModel user = appUserFacade.findByEmail(userEmail);

        if (!securityFacade.isTokenValid(refreshToken, userEmail)) {
            log.info("User with email: " + userEmail + " used an expired token.");
            throw new CredentialsExpiredException("Token expired.");
        }

        var accessToken = securityFacade.generateAccessToken(user);
        Date refreshTokenExpiresAt = securityFacade.extractExpiresAt(refreshToken);

        log.info("User with email: " + userEmail + " refreshed access token.");
        return LoginResponse.builder()
                .accessToken(accessToken.token())
                .accessTokenExpiresAt(accessToken.expiresAt())
                .refreshToken(refreshToken)
                .refreshTokenExpiresAt(refreshTokenExpiresAt)
                .build();
    }

    public AuthReqRespDTO updateUser(String accessToken, AppUserWriteModel toWrite) throws Exception {
        securityFacade.isAccessToken(accessToken);

        String userEmail = securityFacade.extractUsername(accessToken);
        AppUserReadModel appUserFromDataBase = appUserFacade.findByEmail(userEmail);

        if (!securityFacade.isTokenValid(accessToken, userEmail)) {
            log.info("User with email: " + userEmail + " used an expired token.");
            throw new CredentialsExpiredException("Token expired.");
        }

        AuthReqRespDTO responseDTO = new AuthReqRespDTO();

        String firstName = toWrite.getFirstName().isBlank() ?
                appUserFromDataBase.firstName() :
                toWrite.getFirstName();
        String lastName = toWrite.getLastName().isBlank() ?
                appUserFromDataBase.lastName() :
                toWrite.getLastName();

        AppUserWriteModel toUpdate = AppUserWriteModel.builder()
                .id(appUserFromDataBase.id())
                .email(appUserFromDataBase.email())
                .firstName(firstName)
                .lastName(lastName)
                .build();

        AppUserReadModel ourUserResult = appUserFacade.updatePersonalData(toUpdate);

        if (ourUserResult.id() != null) {
            responseDTO.setMessage("User update successfully");
            responseDTO.setStatusCode(200);
            responseDTO.setEmail(ourUserResult.email());
            responseDTO.setFirstName(ourUserResult.firstName());
            responseDTO.setLastName(ourUserResult.lastName());
        }

        return responseDTO;
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

    public AuthReqRespDTO updatePassword(String accessToken, AuthReqRespDTO requestDTO) throws BadTokenTypeException, InvalidEmailTypeException, AppUserNotFoundException, EmailNotFoundException {
        securityFacade.isAccessToken(accessToken);

        String userEmail = securityFacade.extractUsername(accessToken);
        AppUserReadModel appUserFromDB = appUserFacade.findByEmail(userEmail);

        String newPassword = requestDTO.getPassword();
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

    private void validConfirmationToken(final Long userId) throws TokenNotFoundException {
        ConfirmationToken confirmationToken = accountCreateFacade.getTokenByUserId(userId);

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
    }
}
