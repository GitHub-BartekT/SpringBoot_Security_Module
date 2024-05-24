package pl.iseebugs.Security.infrastructure.security;

import lombok.AllArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
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
            responseDTO.setStatusCode(500);
            responseDTO.setError(e.getMessage());
        }
        return responseDTO;
    }

    AuthReqRespDTO confirmToken(final String token) {
        ConfirmationToken confirmationToken = confirmationTokenService
                .getToken(token)
                .orElseThrow(() ->
                        new IllegalStateException("token not found"));

        if (confirmationToken.getConfirmedAt() != null) {
            throw new IllegalStateException("email already confirmed");
        }

        LocalDateTime expiredAt = confirmationToken.getExpiresAt();

        if (expiredAt.isBefore(LocalDateTime.now())) {
            throw new IllegalStateException("token expired");
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
            var jwt = jwtUtils.generateToken(userToJWT);
            var refreshToken = jwtUtils.generateRefreshToken(new HashMap<>(), userToJWT);
            response.setStatusCode(200);
            response.setToken(jwt);
            response.setRefreshToken(refreshToken);
            response.setExpirationTime("24Hr");
            response.setMessage("Successfully singed in");
        }catch (Exception e){
            response.setStatusCode(500);
            response.setError(e.getMessage());
        }
        return response;
    }

    AuthReqRespDTO refreshToken(AuthReqRespDTO refreshTokenRegister){
        AuthReqRespDTO response = new AuthReqRespDTO();

        String ourEmail = jwtUtils.extractUsername(refreshTokenRegister.getRefreshToken());
        AppUser user = appUserRepository.findByEmail(ourEmail).orElseThrow();
        UserDetails userToJWT = AppUserMapper.fromEntityToUserDetails(user);
        if (jwtUtils.isTokenValid(refreshTokenRegister.getRefreshToken(), userToJWT)){
            var jwt = jwtUtils.generateToken(userToJWT);
            response.setStatusCode(200);
            response.setToken(jwt);
            response.setRefreshToken(refreshTokenRegister.getRefreshToken());
            response.setExpirationTime("24Hr");
            response.setMessage("Successfully Refreshed Token");
        } else {
        response.setStatusCode(500);
        response.setMessage("Invalid Token");
        }
        return response;
    }

    AuthReqRespDTO deleteUser(final AuthReqRespDTO deleteRequest) {
        AuthReqRespDTO response = new AuthReqRespDTO();

        String userEmail = jwtUtils.extractUsername(deleteRequest.getRefreshToken());
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
