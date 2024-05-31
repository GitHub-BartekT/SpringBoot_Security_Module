package pl.iseebugs.Security.infrastructure.security;

import lombok.AllArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.user.AppUser;
import pl.iseebugs.Security.domain.user.AppUserRepository;
import pl.iseebugs.Security.infrastructure.security.email.EmailSender;
import pl.iseebugs.Security.infrastructure.security.projection.AuthReqRespDTO;
import pl.iseebugs.Security.infrastructure.security.token.ConfirmationToken;
import pl.iseebugs.Security.infrastructure.security.token.ConfirmationTokenService;

import java.time.LocalDateTime;
import java.util.HashMap;
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

    AuthReqRespDTO signUp(AuthReqRespDTO registrationRequest){
        AuthReqRespDTO responseDTO = new AuthReqRespDTO();
        try {
            String firstName = registrationRequest.getFirstName();
            String lastName = registrationRequest.getLastName();
            String email = registrationRequest.getEmail();
            String password = passwordEncoder.encode(registrationRequest.getPassword());
            String roles = "USER";


            if (appUserRepository.findByEmail(email).isPresent()) {
                throw new RuntimeException("User with email: " + email + " already exists");
            }

            AppUserInfoDetails ourUserToSave = new AppUserInfoDetails(
                    firstName,
                    lastName,
                    email,
                    password,
                    roles);
            AppUser ourUserResult = appUserRepository.save(ourUserToSave.toNewAppUser());

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
                responseDTO.setMessage("User created successfully");
                responseDTO.setExpirationTime("15 minutes");
                responseDTO.setStatusCode(200);

                String link = "http://localhost:8080/api/auth/confirm?token=" + token;
                emailSender.send(
                        registrationRequest.getEmail(),
                        buildEmail(registrationRequest.getFirstName(), link));
            }
        } catch (Exception e){
            responseDTO.setStatusCode(409);
            responseDTO.setError(e.getMessage());
        }
        return responseDTO;
    }

    AuthReqRespDTO confirmToken(final String token) {
        ConfirmationToken confirmationToken;
        try {
            confirmationToken = confirmationTokenService
                    .getToken(token)
                    .orElseThrow(() ->
                            new IllegalStateException("token not found"));
        } catch (IllegalStateException e) {
            AuthReqRespDTO response = new AuthReqRespDTO();
            response.setStatusCode(401);
            response.setError("token not found");
            return response;
        }

        if (confirmationToken.getConfirmedAt() != null) {
            AuthReqRespDTO response = new AuthReqRespDTO();
            response.setStatusCode(409);
            response.setError("email already confirmed");
            return response;
        }

        LocalDateTime expiredAt = confirmationToken.getExpiresAt();

        if (expiredAt.isBefore(LocalDateTime.now())) {
            AuthReqRespDTO response = new AuthReqRespDTO();
            response.setStatusCode(401);
            response.setError("token expired");
            return response;
        }

        confirmationTokenService.setConfirmedAt(token);
        appUserRepository.enableAppUser(
                confirmationToken.getAppUser().getEmail());
        AuthReqRespDTO response = new AuthReqRespDTO();
        response.setStatusCode(200);
        response.setMessage("User confirmed");
        return response;
    }

    AuthReqRespDTO signIn(AuthReqRespDTO signingRequest){
        AuthReqRespDTO response = new AuthReqRespDTO();

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            signingRequest.getEmail(),
                            signingRequest.getPassword()));
            var user = appUserRepository.findByEmail(signingRequest.getEmail()).orElseThrow();

            UserDetails userToJWT = AppUserMapper.fromEntityToUserDetails(user);
            var jwt = jwtUtils.generateAccessToken(userToJWT);
            var refreshToken = jwtUtils.generateRefreshToken(userToJWT);
            response.setStatusCode(200);
            response.setToken(jwt);
            response.setRefreshToken(refreshToken);
            response.setExpirationTime("24Hr");
            response.setMessage("Successfully singed in");
        }catch (Exception e){
            response.setStatusCode(404);
            response.setError(e.getMessage());
        }
        return response;
    }

    AuthReqRespDTO refreshToken(String refreshToken){
        AuthReqRespDTO response = new AuthReqRespDTO();
        String ourEmail = jwtUtils.extractUsername(refreshToken);
        AppUser user = appUserRepository.findByEmail(ourEmail).orElseThrow();
        UserDetails userToJWT = AppUserMapper.fromEntityToUserDetails(user);

        if (jwtUtils.isTokenValid(refreshToken, userToJWT)
                && jwtUtils.isRefreshToken(refreshToken)){
            var jwt = jwtUtils.generateAccessToken(userToJWT);
            response.setStatusCode(200);
            response.setToken(jwt);
            response.setRefreshToken(refreshToken);
            response.setExpirationTime("60 min");
            response.setMessage("Successfully Refreshed Token");
        } else {
        response.setStatusCode(401);
        response.setMessage("Invalid Token");
            log.info("User with email: " + ourEmail +
                    " used invalid token.");
        }

        log.info("User with email: " + ourEmail + " refreshed access token.");
        return response;
    }

    AuthReqRespDTO updateUser(String refreshToken, AuthReqRespDTO updateRequest) {
        String ourEmail = jwtUtils.extractUsername(refreshToken);
        AppUser user = appUserRepository.findByEmail(ourEmail).orElseThrow();

        AuthReqRespDTO responseDTO = new AuthReqRespDTO();

        try {
            String firstName = updateRequest.getFirstName();
            String lastName = updateRequest.getLastName();
            String email = updateRequest.getEmail();
            String password = passwordEncoder.encode(updateRequest.getPassword());
            String roles = user.getRole();
            Boolean locked = user.getLocked();
            Boolean enabled = user.getEnabled();


            if (appUserRepository.findByEmail(email).isEmpty()) {
               email = updateRequest.getEmail();
            } else {
                email = ourEmail;
            }

            AppUser toUpdate = appUserRepository.findByEmail(ourEmail).orElseThrow();

            if (password != null && !password.trim().isEmpty()) {
                toUpdate.setPassword(passwordEncoder.encode(password));
            }

            toUpdate.setEmail(email);
            toUpdate.setRole(roles);
            toUpdate.setFirstName(firstName);
            toUpdate.setLastName(lastName);
            toUpdate.setEnabled(enabled);
            toUpdate.setLocked(locked);

            AppUser ourUserResult = appUserRepository.save(toUpdate);

            if (ourUserResult.getId() != null){
                responseDTO.setMessage("User update successfully");
                responseDTO.setStatusCode(200);
            }
        } catch (Exception e){
            responseDTO.setStatusCode(500);
            responseDTO.setError(e.getMessage());
        }
        return responseDTO;
    }

    AuthReqRespDTO deleteUser(String accessToken) {
        AuthReqRespDTO response = new AuthReqRespDTO();

        String userEmail = jwtUtils.extractUsername(accessToken);
        AppUser user = appUserRepository.findByEmail(userEmail).orElseThrow();
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
