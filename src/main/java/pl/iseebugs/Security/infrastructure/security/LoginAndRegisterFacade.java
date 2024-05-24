package pl.iseebugs.Security.infrastructure.security;

import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.user.AppUser;
import pl.iseebugs.Security.domain.user.AppUserRepository;
import pl.iseebugs.Security.infrastructure.security.projection.AuthReqRespDTO;
import pl.iseebugs.Security.infrastructure.security.token.ConfirmationToken;
import pl.iseebugs.Security.infrastructure.security.token.ConfirmationTokenService;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@AllArgsConstructor
@Service
class LoginAndRegisterFacade {

    private final AppUserRepository appUserRepository;
    private final PasswordEncoder passwordEncoder;
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
                responseDTO.setMessage("User saved successfully");
                responseDTO.setStatusCode(200);
            }
        }catch (Exception e){
            responseDTO.setStatusCode(500);
            responseDTO.setError(e.getMessage());
        }
        return responseDTO;
    }
}
