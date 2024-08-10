package pl.iseebugs.Security.domain.security;

import lombok.AllArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.account.create.ConfirmationToken;
import pl.iseebugs.Security.domain.account.create.ConfirmationTokenService;
import pl.iseebugs.Security.domain.account.delete.DeleteToken;
import pl.iseebugs.Security.domain.account.delete.DeleteTokenService;
import pl.iseebugs.Security.domain.email.EmailFacade;
import pl.iseebugs.Security.domain.email.EmailType;
import pl.iseebugs.Security.domain.email.InvalidEmailTypeException;
import pl.iseebugs.Security.domain.loginandregister.BadTokenTypeException;
import pl.iseebugs.Security.domain.loginandregister.RegistrationTokenConflictException;
import pl.iseebugs.Security.domain.security.projection.AuthReqRespDTO;
import pl.iseebugs.Security.domain.user.AppUserFacade;
import pl.iseebugs.Security.domain.user.AppUserNotFoundException;
import pl.iseebugs.Security.domain.user.dto.AppUserReadModel;
import pl.iseebugs.Security.domain.user.dto.AppUserWriteModel;

import java.time.LocalDateTime;
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
    private final DeleteTokenService deleteTokenService;
    private final EmailFacade emailFacade;
    private final LoginAndRegisterHelper helper;
    private static Long CONFIRMATION_ACCOUNT_TOKEN_EXPIRATION_TIME = 15L;
    private static Long DELETE_ACCOUNT_TOKEN_EXPIRATION_TIME = 1440L;


    public String passwordEncode (CharSequence rawPassword){
        return passwordEncoder.encode(rawPassword);
    }

    AuthReqRespDTO signIn(AuthReqRespDTO signingRequest) throws TokenNotFoundException, AppUserNotFoundException {
        AuthReqRespDTO response = new AuthReqRespDTO();
        String email = signingRequest.getEmail();
        log.info("user email: " + email);

        var user = appUserFacade.findByEmail(email);

        ConfirmationToken confirmationToken = confirmationTokenService.getTokenByUserId(user.id())
                .orElseThrow(() -> new TokenNotFoundException("Confirmation token not found."));

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

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        email,
                        signingRequest.getPassword()));

        UserDetails userToJWT = AppUserMapperLogin.fromAppUserReadModelToUserDetails(user);
        var jwt = jwtUtils.generateAccessToken(userToJWT);
        var refreshToken = jwtUtils.generateRefreshToken(userToJWT);
        response.setStatusCode(200);
        response.setToken(jwt);
        response.setRefreshToken(refreshToken);
        response.setExpirationTime("24Hr");
        response.setMessage("Successfully singed in");
        return response;
    }

    AuthReqRespDTO refreshToken(String refreshToken) throws Exception {
        helper.validateIsTokenRefresh(refreshToken);

        String userEmail = jwtUtils.extractUsername(refreshToken);
        AppUserReadModel user = appUserFacade.findByEmail(userEmail);
        UserDetails userToJWT = AppUserMapperLogin.fromAppUserReadModelToUserDetails(user);

        if (!jwtUtils.isTokenValid(refreshToken, userToJWT)) {
            log.info("User with email: " + userEmail + " used an expired token.");
            throw new CredentialsExpiredException("Token expired.");
        }

        AuthReqRespDTO response = new AuthReqRespDTO();

        var jwt = jwtUtils.generateAccessToken(userToJWT);
        response.setStatusCode(200);
        response.setToken(jwt);
        response.setRefreshToken(refreshToken);
        response.setExpirationTime("60 min");
        response.setMessage("Successfully Refreshed Token");

        log.info("User with email: " + userEmail + " refreshed access token.");
        return response;
    }

    AuthReqRespDTO updateUser(String accessToken, AuthReqRespDTO updateRequest) throws Exception {
        helper.validateIsTokenAccess(accessToken);

        String userEmail = jwtUtils.extractUsername(accessToken);
        AppUserReadModel appUserFromDataBase = appUserFacade.findByEmail(userEmail);
        UserDetails userToJWT = AppUserMapperLogin.fromAppUserReadModelToUserDetails(appUserFromDataBase);

        if (!jwtUtils.isTokenValid(accessToken, userToJWT)) {
            log.info("User with email: " + userEmail + " used an expired token.");
            throw new CredentialsExpiredException("Token expired.");
        }

        AuthReqRespDTO responseDTO = new AuthReqRespDTO();

        String firstName = updateRequest.getFirstName().isBlank() ?
                appUserFromDataBase.firstName() :
                updateRequest.getFirstName();
        String lastName = updateRequest.getLastName().isBlank() ?
                appUserFromDataBase.lastName() :
                updateRequest.getLastName();

        AppUserWriteModel toUpdate = AppUserWriteModel.builder()
                .id(appUserFromDataBase.id())
                .firstName(firstName)
                .lastName(lastName)
                .build();

        AppUserReadModel ourUserResult = appUserFacade.update(toUpdate);

        if (ourUserResult.id() != null) {
            responseDTO.setMessage("User update successfully");
            responseDTO.setStatusCode(200);
            responseDTO.setEmail(ourUserResult.email());
            responseDTO.setFirstName(ourUserResult.firstName());
            responseDTO.setLastName(ourUserResult.lastName());
        }

        return responseDTO;
    }

    AuthReqRespDTO resetPasswordAndNotify(String accessToken) throws BadTokenTypeException, InvalidEmailTypeException, AppUserNotFoundException {
        helper.validateIsTokenAccess(accessToken);

        String userEmail = jwtUtils.extractUsername(accessToken);
        AppUserReadModel appUserFromDB = appUserFacade.findByEmail(userEmail);

        String newPassword = UUID.randomUUID().toString();
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

    AuthReqRespDTO updatePassword(String accessToken, AuthReqRespDTO requestDTO) throws BadTokenTypeException, InvalidEmailTypeException, AppUserNotFoundException {
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

    AuthReqRespDTO deleteUser(String accessToken) throws Exception {
        helper.validateIsTokenAccess(accessToken);

        String userEmail = jwtUtils.extractUsername(accessToken);

        AppUserReadModel user = appUserFacade.findByEmail(userEmail);
        UserDetails userToJWT = AppUserMapperLogin.fromAppUserReadModelToUserDetails(user);

        if (!jwtUtils.isTokenValid(accessToken, userToJWT)) {
            log.info("User with email: " + userEmail + " used an expired token.");
            throw new CredentialsExpiredException("Token expired.");
        }

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

    AuthReqRespDTO confirmDeleteToken(final String token) throws TokenNotFoundException, AppUserNotFoundException {
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

    private void anonymization(final Long id) throws AppUserNotFoundException {
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
