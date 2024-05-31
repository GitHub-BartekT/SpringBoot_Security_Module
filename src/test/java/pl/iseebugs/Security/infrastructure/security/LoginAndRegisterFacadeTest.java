package pl.iseebugs.Security.infrastructure.security;

import org.assertj.core.api.AssertionsForClassTypes;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;
import pl.iseebugs.Security.domain.user.AppUser;
import pl.iseebugs.Security.domain.user.AppUserRepository;
import pl.iseebugs.Security.infrastructure.security.email.EmailSender;
import pl.iseebugs.Security.infrastructure.security.projection.AuthReqRespDTO;
import pl.iseebugs.Security.infrastructure.security.token.ConfirmationToken;
import pl.iseebugs.Security.infrastructure.security.token.ConfirmationTokenService;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class LoginAndRegisterFacadeTest {

    @Test
    void signUp_should_return_response_with_error_email_already_exists() {
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailSender = mock(EmailSender.class);
        when(passwordEncoder.encode(anyString())).then(returnsFirstArg());
        when(appUserRepository.findByEmail(anyString())).thenReturn(Optional.of(new AppUser()));
        //system under test
        var toTest = new LoginAndRegisterFacade(
                appUserRepository,
                passwordEncoder,
                jwtUtils,
                authenticationManager,
                confirmationTokenService,
                emailSender
                );

        //when
        String email = "foo@bar.com";
        AuthReqRespDTO request = new AuthReqRespDTO();
        request.setFirstName("Foo");
        request.setLastName("Bar");
        request.setEmail(email);
        request.setPassword("foobar");

        AuthReqRespDTO response = toTest.signUp(request);

        //then
        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(409),
                () -> assertThat(response.getError())
                        .isEqualTo("User with email: " + email + " already exists")
        );
    }

    @Test
    void signUp_should_signs_up_new_user() {
        //given
        InMemoryAppUserRepository inMemoryAppUserRepository = new InMemoryAppUserRepository();
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailSender = mock(EmailSender.class);
        when(passwordEncoder.encode(anyString())).then(returnsFirstArg());
        doNothing().when(confirmationTokenService).saveConfirmationToken(any(ConfirmationToken.class));
        doNothing().when(emailSender).send(anyString(),anyString());
        //system under test
        var toTest = new LoginAndRegisterFacade(
                inMemoryAppUserRepository,
                passwordEncoder,
                jwtUtils,
                authenticationManager,
                confirmationTokenService,
                emailSender
        );

        //when
        String email = "foo@bar.com";
        AuthReqRespDTO request = new AuthReqRespDTO();
        request.setFirstName("Foo");
        request.setLastName("Bar");
        request.setEmail(email);
        request.setPassword("foobar");

        AuthReqRespDTO response = toTest.signUp(request);

        //then
        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(200),
                () -> assertThat(response.getMessage()).isEqualTo("User created successfully"),
                () -> assertThat(response.getExpirationTime()).isEqualTo("15 minutes")
        );
    }

    @Test
    void confirmToken_should_return_token_not_found() {
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailSender = mock(EmailSender.class);

        when(confirmationTokenService.getToken(anyString())).thenReturn(Optional.empty());
        //system under test
        var toTest = new LoginAndRegisterFacade(
                appUserRepository,
                passwordEncoder,
                jwtUtils,
                authenticationManager,
                confirmationTokenService,
                emailSender
        );
        //when
        String token = "foo";
        AuthReqRespDTO response = toTest.confirmToken(token);

        //then
        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(401),
                () -> assertThat(response.getError())
                        .isEqualTo("token not found")
        );
    }

    @Test
    void signIn() {
    }

    @Test
    void refreshToken() {
    }

    @Test
    void updateUser() {
    }

    @Test
    void deleteUser() {
    }
}