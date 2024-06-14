package pl.iseebugs.Security.infrastructure.security;

import lombok.AllArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.security.authentication.*;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.user.AppUser;
import pl.iseebugs.Security.domain.user.AppUserRepository;
import pl.iseebugs.Security.infrastructure.email.EmailSender;
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
    private final EmailSender emailSender;

    AuthReqRespDTO signUp(AuthReqRespDTO registrationRequest) throws EmailConflictException {
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
                LocalDateTime.now().plusMinutes(15),
                ourUserResult
        );

        confirmationTokenService.saveConfirmationToken(confirmationToken);
        responseDTO.setToken(token);

        if (ourUserResult.getId() != null){
            responseDTO.setMessage("User created successfully.");
            responseDTO.setExpirationTime("15 minutes");
            responseDTO.setStatusCode(201);

            String link = "http://localhost:8080/api/auth/confirm?token=" + token;
            emailSender.send(
                    registrationRequest.getEmail(),
                    "Confirm your email",
                    buildEmail(registrationRequest.getFirstName(), link));
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
            log.info("Token already confirmed.");
            throw new CredentialsExpiredException("Token expired.");
        }

        confirmationTokenService.setConfirmedAt(token);
        appUserRepository.enableAppUser(
                confirmationToken.getAppUser().getEmail());

        response.setStatusCode(200);
        response.setMessage("User confirmed.");
        return response;
    }

    AuthReqRespDTO signIn(AuthReqRespDTO signingRequest){
        AuthReqRespDTO response = new AuthReqRespDTO();

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            signingRequest.getEmail(),
                            signingRequest.getPassword()));
        } catch (UsernameNotFoundException e) {
            log.info(e.getClass().getSimpleName() + ": " + e.getMessage());
            throw new UsernameNotFoundException("User not found.");
        } catch (BadCredentialsException e) {
            log.info(e.getClass().getSimpleName() + ": " + e.getMessage());
            throw new BadCredentialsException("Bad credentials.");
        }  catch (InternalAuthenticationServiceException e) {
            response.setStatusCode(500);
            log.info(e.getClass().getSimpleName() + ": " + e.getMessage());
            response.setError("Internal authentication service error.");
        } catch (Exception e) {
            response.setStatusCode(500);
            log.info(e.getClass().getSimpleName() + ": " + e.getMessage());
            response.setError("An unexpected error occurred.");
        }

        var user = appUserRepository.findByEmail(signingRequest
                        .getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("User not found after authentication."));

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

        String firstName = updateRequest.getFirstName();
        String lastName = updateRequest.getLastName();
        String password = passwordEncoder.encode(updateRequest.getPassword());

        if (password != null && !password.trim().isEmpty()) {
            toUpdate.setPassword(passwordEncoder.encode(password));
        }

        toUpdate.setFirstName(firstName);
        toUpdate.setLastName(lastName);
        AppUser ourUserResult = appUserRepository.save(toUpdate);

        if (ourUserResult.getId() != null){
            responseDTO.setMessage("User update successfully");
            responseDTO.setStatusCode(200);
            responseDTO.setFirstName(ourUserResult.getFirstName());
            responseDTO.setLastName(ourUserResult.getLastName());
        }

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

        AuthReqRespDTO response = new AuthReqRespDTO();

        confirmationTokenService.deleteConfirmationToken(user);
        appUserRepository.deleteByEmail(userEmail);
        response.setStatusCode(204);
        response.setMessage("Successfully deleted user");
        return response;
    }

    private String buildEmail(String name, String link) {
        return  "<div style=\"font-family:Helvetica,Arial,sans-serif;font-size:16px;margin:0;color:#0b0c0c\">\n" +
                "  <table role=\"presentation\" class=\"m_-6186904992287805515content\" align=\"center\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"border-collapse:collapse;max-width:580px;width:100%!important\" width=\"100%\">\n" +
                "    <tbody>\n" +
                "      <tr>\n" +
                "        <td height=\"30\"><br></td>\n" +
                "      </tr>\n" +
                "      <tr>\n" +
                "        <td width=\"10\" valign=\"middle\"><br></td>\n" +
                "        <td style=\"font-family:Helvetica,Arial,sans-serif;font-size:19px;line-height:1.315789474;max-width:560px\">\n" +
                "          <p style=\"Margin:0 0 20px 0;font-size:19px;line-height:25px;color:#0b0c0c\">Hi " + name + ",</p>\n" +
                "          <p style=\"Margin:0 0 20px 0;font-size:19px;line-height:25px;color:#0b0c0c\"> Thank you for registering. Please click on the below link to activate your account: </p>\n" +
                "          <blockquote style=\"Margin:0 0 20px 0;border-left:10px solid #b1b4b6;padding:15px 0 0.1px 15px;font-size:19px;line-height:25px\">\n" +
                "            <p style=\"Margin:0 0 20px 0;font-size:19px;line-height:25px;color:#0b0c0c\">\n" +
                "              <a href=\"" + link + "\">Activate Now</a>\n" +
                "            </p>\n" +
                "          </blockquote>\n" +
                "          Link will expire in 15 minutes.\n" +
                "          <p>See you soon</p>\n" +
                "        </td>\n" +
                "        <td width=\"10\" valign=\"middle\"><br></td>\n" +
                "      </tr>\n" +
                "      <tr>\n" +
                "        <td height=\"30\"><br></td>\n" +
                "      </tr>\n" +
                "    </tbody>\n" +
                "  </table>\n" +
                "  <div class=\"yj6qo\"></div>\n" +
                "  <div class=\"adL\"></div>\n" +
                "</div>";
    }
}
