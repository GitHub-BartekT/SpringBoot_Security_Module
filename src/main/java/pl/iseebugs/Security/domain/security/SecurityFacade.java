package pl.iseebugs.Security.domain.security;

import lombok.AllArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.account.BadTokenTypeException;
import pl.iseebugs.Security.domain.account.EmailNotFoundException;
import pl.iseebugs.Security.domain.account.create.ConfirmationTokenService;
import pl.iseebugs.Security.domain.email.EmailFacade;
import pl.iseebugs.Security.domain.email.EmailType;
import pl.iseebugs.Security.domain.email.InvalidEmailTypeException;
import pl.iseebugs.Security.domain.security.projection.AuthReqRespDTO;
import pl.iseebugs.Security.domain.user.AppUserFacade;
import pl.iseebugs.Security.domain.user.AppUserNotFoundException;
import pl.iseebugs.Security.domain.user.dto.AppUserReadModel;
import pl.iseebugs.Security.domain.user.dto.AppUserWriteModel;

import java.util.UUID;


@AllArgsConstructor
@Service
@Log
public class SecurityFacade {

    private final AppUserFacade appUserFacade;
    private final PasswordEncoder passwordEncoder;
    private final JWTUtils jwtUtils;
    private final AuthenticationManager authenticationManager;
    private final ConfirmationTokenService confirmationTokenService;
    private final EmailFacade emailFacade;
    private final LoginAndRegisterHelper helper;


    public String passwordEncode(CharSequence rawPassword) {
        return passwordEncoder.encode(rawPassword);
    }

    public String extractUsername(String token) {
        return jwtUtils.extractUsername(token);
    }

    public void isAccessToken(String accessToken) throws BadTokenTypeException {
        if (jwtUtils.isAccessToken(accessToken)) {
            return;
        }
        log.info("The provided token is not an access token.");
        throw new BadTokenTypeException();
    }

    public void isRefreshToken(String refreshToken) throws BadTokenTypeException {
        if (jwtUtils.isRefreshToken(refreshToken)) {
            return;
        }
        log.info("The provided token is not an refresh token.");
        throw new BadTokenTypeException();
    }

    public void isTokenExpired(String accessToken) {
        String userEmail = extractUsername(accessToken);
        if (jwtUtils.isTokenExpired(accessToken)) {
            log.info("User with email: " + userEmail + " used an expired token.");
            throw new CredentialsExpiredException("Token expired.");
        }
    }

    public String generateAccessToken(AppUserReadModel appUserReadModel){
        UserDetails userToJWT = AppUserMapperLogin.fromAppUserReadModelToUserDetails(appUserReadModel);
        return jwtUtils.generateAccessToken(userToJWT);
    }

    public String generateRefreshToken(AppUserReadModel appUserReadModel){
        UserDetails userToJWT = AppUserMapperLogin.fromAppUserReadModelToUserDetails(appUserReadModel);
        return jwtUtils.generateRefreshToken(userToJWT);
    }

    public void authenticateByAuthenticationManager (String email, String password){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        email,
                        password));
    }

    public boolean isTokenValid(String token, String email){
        return jwtUtils.isTokenValid(token, email);
    }

    AuthReqRespDTO updateUser(String accessToken, AppUserWriteModel toWrite) throws Exception {
        helper.validateIsTokenAccess(accessToken);

        String userEmail = jwtUtils.extractUsername(accessToken);
        AppUserReadModel appUserFromDataBase = appUserFacade.findByEmail(userEmail);
        UserDetails userToJWT = AppUserMapperLogin.fromAppUserReadModelToUserDetails(appUserFromDataBase);

        if (!jwtUtils.isTokenValid(accessToken, userToJWT)) {
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

    AuthReqRespDTO updatePassword(String accessToken, AuthReqRespDTO requestDTO) throws BadTokenTypeException, InvalidEmailTypeException, AppUserNotFoundException, EmailNotFoundException {
        helper.validateIsTokenAccess(accessToken);

        String userEmail = jwtUtils.extractUsername(accessToken);
        AppUserReadModel appUserFromDB = appUserFacade.findByEmail(userEmail);

        String newPassword = requestDTO.getPassword();
        String encodePassword = passwordEncoder.encode(newPassword);

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
