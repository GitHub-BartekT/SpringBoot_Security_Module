package pl.iseebugs.Security.domain.account.lifecycle;

import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.account.EmailNotFoundException;
import pl.iseebugs.Security.domain.account.TokenNotFoundException;
import pl.iseebugs.Security.domain.account.create.AccountCreateFacade;
import pl.iseebugs.Security.domain.account.create.ConfirmationToken;
import pl.iseebugs.Security.domain.account.lifecycle.dto.AppUserUpdateModel;
import pl.iseebugs.Security.domain.account.lifecycle.dto.LoginRequest;
import pl.iseebugs.Security.domain.account.lifecycle.dto.LoginResponse;
import pl.iseebugs.Security.domain.email.EmailFacade;
import pl.iseebugs.Security.domain.email.EmailType;
import pl.iseebugs.Security.domain.email.InvalidEmailTypeException;
import pl.iseebugs.Security.domain.security.SecurityFacade;
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
        securityFacade.authenticateByAuthenticationManager(email, password);
        validConfirmationToken(user.id());

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
        AppUserReadModel user = getAppUserReadModelFromToken(refreshToken);

        var accessToken = securityFacade.generateAccessToken(user);
        Date refreshTokenExpiresAt = securityFacade.extractExpiresAt(refreshToken);

        return LoginResponse.builder()
                .accessToken(accessToken.token())
                .accessTokenExpiresAt(accessToken.expiresAt())
                .refreshToken(refreshToken)
                .refreshTokenExpiresAt(refreshTokenExpiresAt)
                .build();
    }

    public AppUserUpdateModel updateUser(String accessToken, AppUserWriteModel toWrite) throws Exception {
        AppUserReadModel appUserFromDataBase = getAppUserReadModelFromToken(accessToken);

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

        return AppUserUpdateModel.builder()
                .id(ourUserResult.id())
                .firstName(ourUserResult.firstName())
                .lastName(ourUserResult.lastName())
                .email(ourUserResult.email())
                .build();
    }

    public void resetPasswordAndNotify(String accessToken) throws InvalidEmailTypeException, AppUserNotFoundException, EmailNotFoundException {
        AppUserReadModel appUserFromDB = getAppUserReadModelFromToken(accessToken);
        String newPassword = UUID.randomUUID().toString();
        updatePasswordAndNotify(newPassword, appUserFromDB);
    }

    public void updatePassword(String accessToken, String newPassword) throws InvalidEmailTypeException, AppUserNotFoundException, EmailNotFoundException {
        AppUserReadModel appUserFromDB = getAppUserReadModelFromToken(accessToken);
        updatePasswordAndNotify(newPassword, appUserFromDB);
    }

    private void updatePasswordAndNotify(final String newPassword, final AppUserReadModel appUserFromDB) throws AppUserNotFoundException, EmailNotFoundException, InvalidEmailTypeException {
        String encodePassword = securityFacade.passwordEncode(newPassword);

        AppUserWriteModel toUpdate = AppUserWriteModel.builder()
                .id(appUserFromDB.id())
                .password(encodePassword)
                .build();

        AppUserReadModel updated = appUserFacade.update(toUpdate);

        AppUserUpdateModel responseDTO = AppUserUpdateModel.builder()
                .firstName(updated.firstName())
                .lastName(updated.lastName())
                .email(updated.email())
                .build();

        emailFacade.sendTemplateEmail(
                EmailType.RESET,
                responseDTO,
                newPassword);
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

    private AppUserReadModel getAppUserReadModelFromToken(final String accessToken) throws EmailNotFoundException {
        String userEmail = securityFacade.extractUsername(accessToken);
        return appUserFacade.findByEmail(userEmail);
    }
}
