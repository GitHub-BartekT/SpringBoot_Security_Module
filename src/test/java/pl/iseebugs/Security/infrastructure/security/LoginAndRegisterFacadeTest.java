package pl.iseebugs.Security.infrastructure.security;

import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import pl.iseebugs.Security.domain.user.AppUser;
import pl.iseebugs.Security.domain.user.AppUserRepository;
import pl.iseebugs.Security.infrastructure.security.email.EmailSender;
import pl.iseebugs.Security.infrastructure.security.projection.AuthReqRespDTO;
import pl.iseebugs.Security.infrastructure.security.token.ConfirmationToken;
import pl.iseebugs.Security.infrastructure.security.token.ConfirmationTokenService;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class LoginAndRegisterFacadeTest {

    @Test
    void signUp_should_return_EmailConflictException_409() {
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
                () -> assertThat(response.getError()).isEqualTo("EmailConflictException"),
                () -> assertThat(response.getMessage())
                        .isEqualTo("The email address already exists.")
        );
    }

    @Test
    void signUp_should_signs_up_new_user_and_returns_created_201() {
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
                () -> assertThat(response.getStatusCode()).isEqualTo(201),
                () -> assertThat(response.getMessage()).isEqualTo("User created successfully."),
                () -> assertThat(response.getExpirationTime()).isEqualTo("15 minutes")
        );
    }

    @Test
    void confirmToken_should_returns_BadCredentialException_401() {
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
                () -> assertThat(response.getError()).isEqualTo("BadCredentialsException"),
                () -> assertThat(response.getMessage()).isEqualTo("Token not found.")
        );
    }

    @Test
    void confirmToken_should_returns_Conflict_409() {
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailSender = mock(EmailSender.class);

        LocalDateTime tokenConfirmedAt = LocalDateTime.of(2024,6,3,12,30);
        ConfirmationToken confirmationToken = new ConfirmationToken();
        confirmationToken.setConfirmedAt(tokenConfirmedAt);

        when(confirmationTokenService.getToken(anyString())).thenReturn(Optional.of(confirmationToken));
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
                () -> assertThat(response.getStatusCode()).isEqualTo(409),
                () -> assertThat(response.getError()).isEqualTo("RegistrationTokenConflictException"),
                () -> assertThat(response.getMessage()).isEqualTo("Email already confirm.")
        );
    }

    @Test
    void confirmToken_should_returns_CredentialsExpiredException_403() {
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailSender = mock(EmailSender.class);

        LocalDateTime tokenExpiredAt = LocalDateTime.of(2024,6,3,12,30);
        ConfirmationToken confirmationToken = new ConfirmationToken();
        confirmationToken.setExpiresAt(tokenExpiredAt);
        when(confirmationTokenService.getToken(anyString())).thenReturn(Optional.of(confirmationToken));
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
                () -> assertThat(response.getStatusCode()).isEqualTo(403),
                () -> assertThat(response.getError()).isEqualTo("CredentialsExpiredException"),
                () -> assertThat(response.getMessage()).isEqualTo("Token expired.")
        );
    }

    @Test
    void confirmToken_should_confirms_and_returns_200() {
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailSender = mock(EmailSender.class);

        LocalDateTime tokenExpiresAt = LocalDateTime.of(2024,6,3,12,30);
        AppUser appUser = new AppUser();
        appUser.setEmail("bar");
        ConfirmationToken confirmationToken = new ConfirmationToken();
        confirmationToken.setExpiresAt(tokenExpiresAt);
        confirmationToken.setAppUser(appUser);

        when(confirmationTokenService.getToken(anyString())).thenReturn(Optional.of(confirmationToken));
        doNothing().when(appUserRepository).enableAppUser(anyString());
        LocalDateTime fixedNow = LocalDateTime.of(2024, 6, 3, 12,20);

        // Stub LocalDateTime.now()
        try (MockedStatic<LocalDateTime> mockedLocalDateTime = Mockito.mockStatic(LocalDateTime.class)) {
            mockedLocalDateTime.when(LocalDateTime::now).thenReturn(fixedNow);

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
                    () -> assertThat(response.getStatusCode()).isEqualTo(200),
                    () -> assertThat(response.getMessage()).isEqualTo("User confirmed.")
            );
        }
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