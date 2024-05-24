package pl.iseebugs.Security.infrastructure.security;

import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.user.AppUser;
import pl.iseebugs.Security.domain.user.AppUserRepository;
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
class LoginAndRegisterFacade {

    private final AppUserRepository appUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTUtils jwtUtils;
    private final AuthenticationManager authenticationManager;
    private final ConfirmationTokenService confirmationTokenService;

    AuthReqRespDTO signUp(AuthReqRespDTO registrationRequest){
        AuthReqRespDTO responseDTO = new AuthReqRespDTO();
        try {
            String firstName = registrationRequest.getFirstName();
            String lastName = registrationRequest.getLastName();
            String email = registrationRequest.getEmail();
            String password = passwordEncoder.encode(registrationRequest.getPassword());
            List<GrantedAuthority> roles = new ArrayList<>();
            roles.add(new SimpleGrantedAuthority("USER"));


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
            }
        }catch (Exception e){
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

        String ourEmail = jwtUtils.extractUsername(refreshTokenRegister.getToken());
        AppUser user = appUserRepository.findByEmail(ourEmail).orElseThrow();
        UserDetails userToJWT = AppUserMapper.fromEntityToUserDetails(user);
        if (jwtUtils.isTokenValid(refreshTokenRegister.getToken(), userToJWT)){
            var jwt = jwtUtils.generateToken(userToJWT);
            response.setStatusCode(200);
            response.setToken(jwt);
            response.setRefreshToken(refreshTokenRegister.getToken());
            response.setExpirationTime("5 minutes");
            response.setMessage("Successfully Refreshed Token");
        }
        response.setStatusCode(500);
        return response;
    }
}
