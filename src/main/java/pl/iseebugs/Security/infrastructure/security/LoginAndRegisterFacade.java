package pl.iseebugs.Security.infrastructure.security;

import lombok.AllArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.user.AppUser;
import pl.iseebugs.Security.domain.user.AppUserRepository;
import pl.iseebugs.Security.infrastructure.email.EmailFacade;
import pl.iseebugs.Security.infrastructure.email.EmailType;
import pl.iseebugs.Security.infrastructure.email.InvalidEmailTypeException;
import pl.iseebugs.Security.infrastructure.security.deleteToken.DeleteToken;
import pl.iseebugs.Security.infrastructure.security.deleteToken.DeleteTokenService;
import pl.iseebugs.Security.infrastructure.security.projection.AuthReqRespDTO;
import pl.iseebugs.Security.infrastructure.security.token.ConfirmationToken;
import pl.iseebugs.Security.infrastructure.security.token.ConfirmationTokenService;

import java.time.LocalDateTime;
import java.util.UUID;

@AllArgsConstructor
@Service
@Log
class LoginAndRegisterFacade {

    private final AppUserRepository appUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTUtils jwtUtils;
    private final AuthenticationManager authenticationManager;
    private final ConfirmationTokenService confirmationTokenService;
    private final DeleteTokenService deleteTokenService;
    private final EmailFacade emailFacade;
    private final AppProperties appProperties;
    private static Long CONFIRMATION_ACCOUNT_TOKEN_EXPIRATION_TIME = 15L;
    private static Long DELETE_ACCOUNT_TOKEN_EXPIRATION_TIME = 1440L;


    AuthReqRespDTO signUp(AuthReqRespDTO registrationRequest) throws EmailConflictException, InvalidEmailTypeException {
        AuthReqRespDTO responseDTO = new AuthReqRespDTO();

        String firstName = registrationRequest.getFirstName();
        String lastName = registrationRequest.getLastName();
        String email = registrationRequest.getEmail();
        String password = passwordEncoder.encode(registrationRequest.getPassword());
        String roles = "USER";

        if (appUserRepository.findByEmail(email).isPresent()) {
            throw new EmailConflictException();
        }

        AppUserInfoDetails userToSave = new AppUserInfoDetails(
                firstName,
                lastName,
                email,
                password,
                roles);

        AppUser ourUserResult = appUserRepository.save(userToSave.toNewAppUser());

        String token = UUID.randomUUID().toString();

        ConfirmationToken confirmationToken = new ConfirmationToken(
                token,
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(CONFIRMATION_ACCOUNT_TOKEN_EXPIRATION_TIME),
                ourUserResult
        );

        confirmationTokenService.saveConfirmationToken(confirmationToken);
        responseDTO.setToken(token);

        if (ourUserResult.getId() != null) {
            responseDTO.setMessage("User created successfully.");
            responseDTO.setExpirationTime("15 minutes");
            responseDTO.setStatusCode(201);

            String link = createUrl("/api/auth/confirm?token=", token);

            emailFacade.sendTemplateEmail(
                    EmailType.ACTIVATION,
                    registrationRequest,
                    link);
        }
        return responseDTO;
    }

    AuthReqRespDTO confirmToken(final String token) throws TokenNotFoundException, RegistrationTokenConflictException {
        ConfirmationToken confirmationToken;
        confirmationToken = confirmationTokenService.getToken(token)
                .orElseThrow(TokenNotFoundException::new);

        if (confirmationToken.getConfirmedAt() != null) {
            log.info("Confirmation token already confirmed.");
            throw new RegistrationTokenConflictException();
        }

        AuthReqRespDTO response = new AuthReqRespDTO();
        LocalDateTime expiredAt = confirmationToken.getExpiresAt();

        if (expiredAt.isBefore(LocalDateTime.now())) {
            log.info("Token expired.");
            throw new CredentialsExpiredException("Token expired.");
        }

        confirmationTokenService.setConfirmedAt(token);
        appUserRepository.enableAppUser(
                confirmationToken.getAppUser().getEmail());
        response.setStatusCode(200);
        response.setMessage("User confirmed.");
        return response;
    }

    AuthReqRespDTO signIn(AuthReqRespDTO signingRequest) throws TokenNotFoundException {
        AuthReqRespDTO response = new AuthReqRespDTO();
        String email = signingRequest.getEmail();
        log.info("user email: " + email);

        var user = appUserRepository
                .findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found."));

        ConfirmationToken confirmationToken = confirmationTokenService.getTokenByEmail(email)
                .orElseThrow(() -> new TokenNotFoundException("Confirmation token not found."));

        LocalDateTime expiredAt = confirmationToken.getExpiresAt();

        if (confirmationToken.getConfirmedAt() == null) {
            if (expiredAt.isBefore(LocalDateTime.now())) {
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

        UserDetails userToJWT = AppUserMapper.fromEntityToUserDetails(user);
        var jwt = jwtUtils.generateAccessToken(userToJWT);
        var refreshToken = jwtUtils.generateRefreshToken(userToJWT);
        response.setStatusCode(200);
        response.setToken(jwt);
        response.setRefreshToken(refreshToken);
        response.setExpirationTime("24Hr");
        response.setMessage("Successfully singed in");
        return response;
    }

    AuthReqRespDTO refreshConfirmationToken(String email) throws InvalidEmailTypeException, TokenNotFoundException, RegistrationTokenConflictException {
        AuthReqRespDTO responseDTO = new AuthReqRespDTO();
        responseDTO.setEmail(email);

        AppUser appUserResult = appUserRepository.findByEmail(email).
                orElseThrow(() -> new UsernameNotFoundException("Email not found."));
        responseDTO.setFirstName(appUserResult.getFirstName());
        responseDTO.setLastName(appUserResult.getLastName());

        String token = UUID.randomUUID().toString();
        responseDTO.setToken(token);

        if (confirmationTokenService.getTokenByEmail(email).isEmpty()) {
            ConfirmationToken confirmationToken = new ConfirmationToken(
                    token,
                    LocalDateTime.now(),
                    LocalDateTime.now().plusMinutes(CONFIRMATION_ACCOUNT_TOKEN_EXPIRATION_TIME),
                    appUserResult
            );
            confirmationTokenService.saveConfirmationToken(confirmationToken);
            responseDTO.setStatusCode(201);
        } else if (confirmationTokenService.isConfirmed(email)) {
            log.info("Confirmation token already confirmed.");
            throw new RegistrationTokenConflictException("Confirmation token already confirmed.");
        } else {
            ConfirmationToken confirmationToken = confirmationTokenService.getTokenByEmail(email)
                    .orElseThrow(() -> new TokenNotFoundException("Confirmation token not found."));

            confirmationToken.setCreatedAt(LocalDateTime.now());
            confirmationToken.setExpiresAt(LocalDateTime.now().plusMinutes(CONFIRMATION_ACCOUNT_TOKEN_EXPIRATION_TIME));
            responseDTO.setStatusCode(204);
        }

        responseDTO.setMessage("Generated new confirmation token.");
        responseDTO.setExpirationTime("15 minutes");

        String link = createUrl("/api/auth/confirm?token=", token);

        emailFacade.sendTemplateEmail(EmailType.ACTIVATION, responseDTO, link);

        return responseDTO;
    }

    AuthReqRespDTO refreshToken(String refreshToken) throws Exception {
        if (!jwtUtils.isRefreshToken(refreshToken)) {
            log.info("Bad token type provided.");
            throw new BadTokenTypeException();
        }

        String userEmail = jwtUtils.extractUsername(refreshToken);
        AppUser user = appUserRepository.findByEmail(userEmail)
                .orElseThrow(() -> new UsernameNotFoundException("User extracted from token not found."));
        UserDetails userToJWT = AppUserMapper.fromEntityToUserDetails(user);

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
        if (jwtUtils.isRefreshToken(accessToken)) {
            log.info("Bad token type provided.");
            throw new BadTokenTypeException();
        }

        String userEmail = jwtUtils.extractUsername(accessToken);
        AppUser toUpdate = appUserRepository.findByEmail(userEmail)
                .orElseThrow(() ->
                        new UsernameNotFoundException("User extracted from token not found."));
        UserDetails userToJWT = AppUserMapper.fromEntityToUserDetails(toUpdate);

        if (!jwtUtils.isTokenValid(accessToken, userToJWT)) {
            log.info("User with email: " + userEmail + " used an expired token.");
            throw new CredentialsExpiredException("Token expired.");
        }

        AuthReqRespDTO responseDTO = new AuthReqRespDTO();

        String firstName = updateRequest.getFirstName().isBlank() ?
                toUpdate.getFirstName() :
                updateRequest.getFirstName();

        String lastName = updateRequest.getLastName().isBlank() ?
                toUpdate.getLastName() :
                updateRequest.getLastName();

        toUpdate.setFirstName(firstName);
        toUpdate.setLastName(lastName);
        AppUser ourUserResult = appUserRepository.save(toUpdate);

        if (ourUserResult.getId() != null) {
            responseDTO.setMessage("User update successfully");
            responseDTO.setStatusCode(200);
            responseDTO.setEmail(ourUserResult.getEmail());
            responseDTO.setFirstName(ourUserResult.getFirstName());
            responseDTO.setLastName(ourUserResult.getLastName());
            responseDTO.setFirstName(ourUserResult.getFirstName());
            responseDTO.setLastName(ourUserResult.getLastName());
        }

        return responseDTO;
    }

    AuthReqRespDTO generateNewPassword(String accessToken) throws BadTokenTypeException, InvalidEmailTypeException {
        if (jwtUtils.isRefreshToken(accessToken)) {
            log.info("Bad token type provided.");
            throw new BadTokenTypeException();
        }

        String userEmail = jwtUtils.extractUsername(accessToken);
        AppUser toUpdate = appUserRepository.findByEmail(userEmail)
                .orElseThrow(() ->
                        new UsernameNotFoundException("User extracted from token not found."));

        String newPassword = UUID.randomUUID().toString();
        String encodePassword = passwordEncoder.encode(newPassword);

        toUpdate.setPassword(encodePassword);
        appUserRepository.save(toUpdate);

        AuthReqRespDTO responseDTO = new AuthReqRespDTO();

        responseDTO.setMessage("Password changed successfully");
        responseDTO.setStatusCode(200);
        responseDTO.setFirstName(toUpdate.getFirstName());
        responseDTO.setLastName(toUpdate.getLastName());
        responseDTO.setEmail(toUpdate.getEmail());

        emailFacade.sendTemplateEmail(
                EmailType.RESET,
                responseDTO,
                newPassword);

        return responseDTO;
    }

    AuthReqRespDTO deleteUser(String accessToken) throws Exception {
        if (jwtUtils.isRefreshToken(accessToken)) {
            log.info("Bad token type provided");
            throw new BadTokenTypeException();
        }

        String userEmail = jwtUtils.extractUsername(accessToken);

        AppUser user = appUserRepository.findByEmail(userEmail)
                .orElseThrow(() ->
                        new UsernameNotFoundException("User extracted from token not found."));
        UserDetails userToJWT = AppUserMapper.fromEntityToUserDetails(user);

        if (!jwtUtils.isTokenValid(accessToken, userToJWT)) {
            log.info("User with email: " + userEmail + " used an expired token.");
            throw new CredentialsExpiredException("Token expired.");
        }

        AuthReqRespDTO responseDTO = new AuthReqRespDTO();
        responseDTO.setFirstName(user.getFirstName());
        responseDTO.setEmail(user.getEmail());

        String token = UUID.randomUUID().toString();

        DeleteToken deleteToken = deleteTokenService.getTokenByEmail(userEmail).isPresent() ?
                deleteTokenService.getTokenByEmail(userEmail).orElseThrow(TokenNotFoundException::new) :
                new DeleteToken();

        deleteToken.setToken(token);
        deleteToken.setCreatedAt(LocalDateTime.now());
        deleteToken.setExpiresAt(LocalDateTime.now().plusMinutes(DELETE_ACCOUNT_TOKEN_EXPIRATION_TIME));
        deleteToken.setAppUser(user);

        deleteTokenService.saveDeleteToken(deleteToken);
        responseDTO.setToken(token);

        responseDTO.setMessage("Delete confirmation mail created successfully.");
        responseDTO.setExpirationTime("24 hours");
        responseDTO.setStatusCode(201);

        String link = createUrl("/api/auth/delete-confirm?token=", token);

        emailFacade.sendTemplateEmail(
                EmailType.DELETE,
                responseDTO,
                link);

        return responseDTO;
    }

    AuthReqRespDTO confirmDeleteToken(final String token) throws TokenNotFoundException {
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

        anonymization(deleteToken.getAppUser().getEmail());

        response.setStatusCode(204);
        response.setMessage("User account successfully deleted.");
        return response;
    }

    private void anonymization(final String email) {
        AppUser user = appUserRepository.findByEmail(email)
                .orElseThrow(() ->
                        new UsernameNotFoundException("User not found."));
        user.setRole("DELETED");
        user.setFirstName(UUID.randomUUID().toString());
        user.setLastName(UUID.randomUUID().toString());
        user.setPassword(UUID.randomUUID().toString());
        user.setEmail(UUID.randomUUID().toString());
        appUserRepository.save(user);
    }

    private String createUrl(final String endpoint, final String token) {
        return appProperties.uri() + ":" +
                appProperties.port() +
                endpoint +
                token;
    }
}
