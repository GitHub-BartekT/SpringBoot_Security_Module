package pl.iseebugs.Security.infrastructure.security;

import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import pl.iseebugs.Security.domain.user.AppUser;
import pl.iseebugs.Security.domain.user.AppUserRepository;
import pl.iseebugs.Security.infrastructure.email.EmailFacade;
import pl.iseebugs.Security.infrastructure.email.InvalidEmailTypeException;
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
    void signUp_should_throws_EmailConflictException(){
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailFacade = mock(EmailFacade.class);
        when(passwordEncoder.encode(anyString())).then(returnsFirstArg());
        when(appUserRepository.findByEmail(anyString())).thenReturn(Optional.of(new AppUser()));
        //system under test
        var toTest = new LoginAndRegisterFacade(
                appUserRepository,
                passwordEncoder,
                jwtUtils,
                authenticationManager,
                confirmationTokenService,
                emailFacade
                );

        //when
        String email = "foo@bar.com";
        AuthReqRespDTO request = new AuthReqRespDTO();
        request.setFirstName("Foo");
        request.setLastName("Bar");
        request.setEmail(email);
        request.setPassword("foobar");

        Throwable e = catchThrowable(() -> toTest.signUp(request));

        //then
        assertAll(
                () -> assertThat(e).isInstanceOf(EmailConflictException.class),
                () -> assertThat(e.getMessage()).isEqualTo("The email address already exists.")
        );
    }

    @Test
    void signUp_should_signs_up_new_user_and_returns_created_201() throws EmailConflictException, InvalidEmailTypeException {
        //given
        InMemoryAppUserRepository inMemoryAppUserRepository = new InMemoryAppUserRepository();
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailFacade = mock(EmailFacade.class);
        when(passwordEncoder.encode(anyString())).then(returnsFirstArg());
        doNothing().when(confirmationTokenService).saveConfirmationToken(any(ConfirmationToken.class));
        doNothing().when(emailFacade).send(anyString(), anyString(), anyString());
        //system under test
        var toTest = new LoginAndRegisterFacade(
                inMemoryAppUserRepository,
                passwordEncoder,
                jwtUtils,
                authenticationManager,
                confirmationTokenService,
                emailFacade
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
    void confirmToken_should_throws_TokenNotFoundException(){
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailFacade = mock(EmailFacade.class);

        when(confirmationTokenService.getToken(anyString())).thenReturn(Optional.empty());
        //system under test
        var toTest = new LoginAndRegisterFacade(
                appUserRepository,
                passwordEncoder,
                jwtUtils,
                authenticationManager,
                confirmationTokenService,
                emailFacade
        );
        //when
        String token = "foo";
        Throwable e = catchThrowable(() -> toTest.confirmToken(token));

        //then
        assertAll(
                () -> assertThat(e).isInstanceOf(TokenNotFoundException.class),
                () -> assertThat(e.getMessage()).isEqualTo("Token not found.")
        );
    }

    @Test
    void confirmToken_should_throws_RegistrationTokenConflictException(){
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailFacade = mock(EmailFacade.class);

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
                emailFacade
        );
        //when
        String token = "foo";
        Throwable e = catchThrowable(() -> toTest.confirmToken(token));

        //then
        assertAll(
                () -> assertThat(e).isInstanceOf(RegistrationTokenConflictException.class),
                () -> assertThat(e.getMessage()).isEqualTo("Token already confirmed.")
        );
    }

    @Test
    void confirmToken_should_throws_CredentialsExpiredException(){
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailFacade = mock(EmailFacade.class);

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
                emailFacade
        );
        //when
        String token = "foo";
        Throwable e = catchThrowable(() -> toTest.confirmToken(token));

        //then
        assertAll(
                () -> assertThat(e).isInstanceOf(CredentialsExpiredException.class),
                () -> assertThat(e.getMessage()).isEqualTo("Token expired.")
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
        var emailFacade = mock(EmailFacade.class);

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
                    emailFacade
            );
            //when
            String token = "foo";
            AuthReqRespDTO response = toTest.confirmToken(token);

            //then
            assertAll(
                    () -> assertThat(response.getStatusCode()).isEqualTo(200),
                    () -> assertThat(response.getMessage()).isEqualTo("User confirmed.")
            );
        } catch (RegistrationTokenConflictException | TokenNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void refreshConfirmationToken_should_throws_UsernameNotFoundException(){
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailFacade = mock(EmailFacade.class);

        //system under test
        var toTest = new LoginAndRegisterFacade(
                appUserRepository,
                passwordEncoder,
                jwtUtils,
                authenticationManager,
                confirmationTokenService,
                emailFacade
        );
        //when
        when(appUserRepository.findByEmail(anyString())).thenReturn(Optional.empty());

        String email = "foo@mail.com";
        Throwable e = catchThrowable(() -> toTest.refreshConfirmationToken(email));

        //then
        assertAll(
                () -> assertThat(e).isInstanceOf(UsernameNotFoundException.class),
                () -> assertThat(e.getMessage()).isEqualTo("Email not found.")
        );
    }

    @Test
    void refreshConfirmationToken_should_throws_RegistrationTokenConflictException() throws TokenNotFoundException {
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailFacade = mock(EmailFacade.class);

        //system under test
        var toTest = new LoginAndRegisterFacade(
                appUserRepository,
                passwordEncoder,
                jwtUtils,
                authenticationManager,
                confirmationTokenService,
                emailFacade
        );
        //when
        when(appUserRepository.findByEmail(anyString())).thenReturn(Optional.of(new AppUser()));
        when(confirmationTokenService.isConfirmed(anyString())).thenReturn(true);


        String email = "foo@mail.com";
        Throwable e = catchThrowable(() -> toTest.refreshConfirmationToken(email));

        //then
        assertAll(
                () -> assertThat(e).isInstanceOf(RegistrationTokenConflictException.class),
                () -> assertThat(e.getMessage()).isEqualTo("Confirmation token already confirmed.")
        );
    }

    @Test
    void refreshConfirmationToken_should_throws_ok_and_201() throws TokenNotFoundException, RegistrationTokenConflictException, InvalidEmailTypeException {
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailFacade = mock(EmailFacade.class);

        //system under test
        var toTest = new LoginAndRegisterFacade(
                appUserRepository,
                passwordEncoder,
                jwtUtils,
                authenticationManager,
                confirmationTokenService,
                emailFacade
        );
        //when
        when(appUserRepository.findByEmail(anyString())).thenReturn(Optional.of(new AppUser()));
        when(confirmationTokenService.isConfirmed(anyString())).thenReturn(false);
        when(confirmationTokenService.getTokenByEmail(anyString())).thenReturn(Optional.empty());
        doNothing().when(confirmationTokenService).saveConfirmationToken(any(ConfirmationToken.class));

        String email = "foo@mail.com";
        AuthReqRespDTO response = toTest.refreshConfirmationToken(email);

        //then
        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(201),
                () -> assertThat(response.getMessage()).isEqualTo("Generated new confirmation token.")
        );
    }

    @Test
    void refreshConfirmationToken_should_returns_ok_and_204() throws TokenNotFoundException, RegistrationTokenConflictException, InvalidEmailTypeException {
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailFacade = mock(EmailFacade.class);

        //system under test
        var toTest = new LoginAndRegisterFacade(
                appUserRepository,
                passwordEncoder,
                jwtUtils,
                authenticationManager,
                confirmationTokenService,
                emailFacade
        );
        //when
        when(appUserRepository.findByEmail(anyString())).thenReturn(Optional.of(new AppUser()));
        when(confirmationTokenService.isConfirmed(anyString())).thenReturn(false);
        when(confirmationTokenService.getTokenByEmail(anyString())).thenReturn(Optional.of(new ConfirmationToken()));
        doNothing().when(confirmationTokenService).saveConfirmationToken(any(ConfirmationToken.class));

        String email = "foo@mail.com";
        AuthReqRespDTO response = toTest.refreshConfirmationToken(email);

        //then
        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(204),
                () -> assertThat(response.getMessage()).isEqualTo("Generated new confirmation token.")
        );
    }

    @Test
    void signIn_should_throws_BadCredentialsException() {
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailFacade = mock(EmailFacade.class);

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Bad credentials."));

        //system under test
        var toTest = new LoginAndRegisterFacade(
                appUserRepository,
                passwordEncoder,
                jwtUtils,
                authenticationManager,
                confirmationTokenService,
                emailFacade
        );

        //when
        AuthReqRespDTO request = new AuthReqRespDTO();
        request.setFirstName("Foo");
        request.setLastName("Bar");
        request.setEmail("test@foo.com");
        request.setPassword("foobar");

        Throwable e = catchThrowable(() -> toTest.signIn(request));

        //then
        assertAll(
                () -> assertThat(e).isInstanceOf(BadCredentialsException.class),
                () -> assertThat(e.getMessage()).isEqualTo("Bad credentials.")
        );
    }

    @Test
    void signIn_should_returns_UsernameNotFoundException() {
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailFacade = mock(EmailFacade.class);

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new UsernameNotFoundException("User not found."));

        //system under test
        var toTest = new LoginAndRegisterFacade(
                appUserRepository,
                passwordEncoder,
                jwtUtils,
                authenticationManager,
                confirmationTokenService,
                emailFacade
        );

        //when
        AuthReqRespDTO request = new AuthReqRespDTO();
        request.setFirstName("Foo");
        request.setLastName("Bar");
        request.setEmail("test@foo.com");
        request.setPassword("foobar");

        Throwable e = catchThrowable(() -> toTest.signIn(request));

        //then
        assertAll(
                () -> assertThat(e).isInstanceOf(UsernameNotFoundException.class),
                () -> assertThat(e.getMessage()).isEqualTo("User not found.")
        );
    }

    @Test
    void signIn_should_signs_in_user_and_returns_ok_200() {
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailFacade = mock(EmailFacade.class);

        AuthReqRespDTO request = new AuthReqRespDTO();
        request.setFirstName("Foo");
        request.setLastName("Bar");
        request.setEmail("test@foo.com");
        request.setPassword("foobar");

        AppUser user = new AppUser();
        user.setEmail(request.getEmail());
        user.setPassword(request.getPassword());
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setRole("USER");
        user.setEnabled(true);

        when(appUserRepository.findByEmail(request.getEmail()))
                .thenReturn(Optional.of(user));

        UserDetails userDetails = AppUserMapper.fromEntityToUserDetails(user);

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities()));

        when(jwtUtils.generateAccessToken(any(UserDetails.class))).thenReturn("jwt-token");
        when(jwtUtils.generateRefreshToken(any(UserDetails.class))).thenReturn("refresh-token");

        //system under test
        var toTest = new LoginAndRegisterFacade(
                appUserRepository,
                passwordEncoder,
                jwtUtils,
                authenticationManager,
                confirmationTokenService,
                emailFacade
        );

        //when
        AuthReqRespDTO response = toTest.signIn(request);

        //then
        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(200),
                () -> assertThat(response.getToken()).isEqualTo("jwt-token"),
                () -> assertThat(response.getRefreshToken()).isEqualTo("refresh-token"),
                () -> assertThat(response.getMessage()).isEqualTo("Successfully singed in")
        );
    }

    @Test
    void refreshToken_should_throws_BadTokenTypeException(){
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailFacade = mock(EmailFacade.class);

        when(jwtUtils.extractUsername(anyString())).thenReturn("foo-email");

        AppUser user = new AppUser();
        user.setFirstName("Foo");
        user.setLastName("Bar");
        user.setEmail("test@foo.com");
        user.setPassword("foobar");
        user.setRole("USER");
        user.setEnabled(true);

        when(appUserRepository.findByEmail(anyString()))
                .thenReturn(Optional.of(user));

        //system under test
        var toTest = new LoginAndRegisterFacade(
                appUserRepository,
                passwordEncoder,
                jwtUtils,
                authenticationManager,
                confirmationTokenService,
                emailFacade
        );

        //when
        String request = "foobar";

        Throwable e = catchThrowable(() -> toTest.refreshToken(request));

        //then
        assertAll(
                () -> assertThat(e).isInstanceOf(BadTokenTypeException.class),
                () -> assertThat(e.getMessage()).isEqualTo("Invalid Token type.")
        );
    }

    @Test
    void refreshToken_should_throws_UserNotFoundException() {
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailFacade = mock(EmailFacade.class);

        when(jwtUtils.isRefreshToken(anyString())).thenReturn(true);
        when(jwtUtils.extractUsername(anyString())).thenReturn("foo-email");

        //system under test
        var toTest = new LoginAndRegisterFacade(
                appUserRepository,
                passwordEncoder,
                jwtUtils,
                authenticationManager,
                confirmationTokenService,
                emailFacade
        );

        //when
        String request = "foobar";

        Throwable e = catchThrowable(() -> toTest.refreshToken(request));

        //then
        assertAll(
                () -> assertThat(e).isInstanceOf(UsernameNotFoundException.class),
                () -> assertThat(e.getMessage()).isEqualTo("User extracted from token not found.")
        );
    }

    @Test
    void refreshToken_should_throws_CredentialsExpiredException(){
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailFacade = mock(EmailFacade.class);

        when(jwtUtils.extractUsername(anyString())).thenReturn("foo-email");

        AppUser user = new AppUser();
        user.setFirstName("Foo");
        user.setLastName("Bar");
        user.setEmail("test@foo.com");
        user.setPassword("foobar");
        user.setRole("USER");
        user.setEnabled(true);

        when(appUserRepository.findByEmail(anyString()))
                .thenReturn(Optional.of(user));

        when(jwtUtils.isRefreshToken(anyString())).thenReturn(true);
        when(jwtUtils.isTokenValid(anyString(), any(UserDetails.class))).thenReturn(false);


        //system under test
        var toTest = new LoginAndRegisterFacade(
                appUserRepository,
                passwordEncoder,
                jwtUtils,
                authenticationManager,
                confirmationTokenService,
                emailFacade
        );

        //when
        String request = "foobar";
        Throwable e = catchThrowable(() -> toTest.refreshToken(request));

        //then
        assertAll(
                () -> assertThat(e).isInstanceOf(CredentialsExpiredException.class),
                () -> assertThat(e.getMessage()).isEqualTo("Token expired.")
        );
    }

    @Test
    void refreshToken_should_returns_accessToken_and_200(){
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailFacade = mock(EmailFacade.class);

        when(jwtUtils.extractUsername(anyString())).thenReturn("foo-email");

        AppUser user = new AppUser();
        user.setFirstName("Foo");
        user.setLastName("Bar");
        user.setEmail("test@foo.com");
        user.setPassword("foobar");
        user.setRole("USER");
        user.setEnabled(true);

        when(appUserRepository.findByEmail(anyString()))
                .thenReturn(Optional.of(user));

        when(jwtUtils.isRefreshToken(anyString())).thenReturn(true);
        when(jwtUtils.isTokenValid(anyString(), any(UserDetails.class))).thenReturn(true);
        when(jwtUtils.generateAccessToken(any(UserDetails.class))).thenReturn("jwt-token");
        when(jwtUtils.generateRefreshToken(any(UserDetails.class))).thenReturn("refresh-token");


        //system under test
        var toTest = new LoginAndRegisterFacade(
                appUserRepository,
                passwordEncoder,
                jwtUtils,
                authenticationManager,
                confirmationTokenService,
                emailFacade
        );

        //when
        AuthReqRespDTO request = new AuthReqRespDTO();
        request.setFirstName("Foo");
        request.setLastName("Bar");
        request.setEmail("test@foo.com");
        request.setPassword("foobar");

        AuthReqRespDTO response = toTest.signIn(request);

        //then
        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(200),
                () -> assertThat(response.getToken()).isEqualTo("jwt-token"),
                () -> assertThat(response.getRefreshToken()).isEqualTo("refresh-token"),
                () -> assertThat(response.getMessage()).isEqualTo("Successfully singed in")
        );
    }

    @Test
    void updateUser_should_throws_BadTokenTypeException() {
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailFacade = mock(EmailFacade.class);

        when(jwtUtils.isRefreshToken(anyString())).thenReturn(true);

        //system under test
        var toTest = new LoginAndRegisterFacade(
                appUserRepository,
                passwordEncoder,
                jwtUtils,
                authenticationManager,
                confirmationTokenService,
                emailFacade
        );

        //when
        String request = "foobar";

        Throwable e = catchThrowable(() -> toTest.updateUser(request, new AuthReqRespDTO()));

        //then
        assertAll(
                () -> assertThat(e).isInstanceOf(BadTokenTypeException.class),
                () -> assertThat(e.getMessage()).isEqualTo("Invalid Token type.")
        );
    }

    @Test
    void updateUser_should_throws_UserNotFoundException() {
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailFacade = mock(EmailFacade.class);
        when(jwtUtils.isRefreshToken(anyString())).thenReturn(false);
        when(jwtUtils.extractUsername(anyString())).thenReturn("foo-email");

        //system under test
        var toTest = new LoginAndRegisterFacade(
                appUserRepository,
                passwordEncoder,
                jwtUtils,
                authenticationManager,
                confirmationTokenService,
                emailFacade
        );

        //when
        String request = "foobar";
        Throwable e = catchThrowable(() -> toTest.updateUser(request, new AuthReqRespDTO()));

        //then
        assertAll(
                () -> assertThat(e).isInstanceOf(UsernameNotFoundException.class),
                () -> assertThat(e.getMessage()).isEqualTo("User extracted from token not found.")
        );
    }

    @Test
    void updateUser_should_throws_CredentialsExpiredException() {
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailFacade = mock(EmailFacade.class);
        when(jwtUtils.isRefreshToken(anyString())).thenReturn(false);
        when(jwtUtils.extractUsername(anyString())).thenReturn("foo-email");
        when(jwtUtils.isTokenValid(anyString(), any(UserDetails.class))).thenReturn(false);

        AppUser user = new AppUser();
        user.setFirstName("Foo");
        user.setLastName("Bar");
        user.setEmail("test@foo.com");
        user.setPassword("foobar");
        user.setRole("USER");
        user.setEnabled(true);

        when(appUserRepository.findByEmail(anyString()))
                .thenReturn(Optional.of(user));

        when(jwtUtils.isTokenValid(anyString(), any(UserDetails.class))).thenReturn(false);

        //system under test
        var toTest = new LoginAndRegisterFacade(
                appUserRepository,
                passwordEncoder,
                jwtUtils,
                authenticationManager,
                confirmationTokenService,
                emailFacade
        );

        //when
        String request = "foobar";
        Throwable e = catchThrowable(() -> toTest.updateUser(request, new AuthReqRespDTO()));

        //then
        assertAll(
                () -> assertThat(e).isInstanceOf(CredentialsExpiredException.class),
                () -> assertThat(e.getMessage()).isEqualTo("Token expired.")
        );
    }

    @Test
    void updateUser_should_returns_ok_200() throws Exception {
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailFacade = mock(EmailFacade.class);
        when(jwtUtils.isRefreshToken(anyString())).thenReturn(false);
        when(jwtUtils.extractUsername(anyString())).thenReturn("foo-email");
        when(jwtUtils.isTokenValid(anyString(), any(UserDetails.class))).thenReturn(true);

        AppUser user = new AppUser();
        user.setFirstName("Foo");
        user.setLastName("Bar");
        user.setEmail("test@foo.com");
        user.setPassword("foobar");
        user.setRole("USER");
        user.setEnabled(true);

        when(appUserRepository.findByEmail(anyString()))
                .thenReturn(Optional.of(user));

        user.setId(123L);
        when(appUserRepository.save(user))
                .thenReturn(user);
        when(passwordEncoder.encode(anyString())).thenReturn("encodePassword");

        //system under test
        var toTest = new LoginAndRegisterFacade(
                appUserRepository,
                passwordEncoder,
                jwtUtils,
                authenticationManager,
                confirmationTokenService,
                emailFacade
        );

        //when
        String token = "foobar";
        AuthReqRespDTO request = new AuthReqRespDTO();
        request.setFirstName("foobar");
        request.setLastName("barfoo");
        request.setEmail("test@foo.com");
        request.setPassword("pass");

        AuthReqRespDTO response = toTest.updateUser(token, request);

        //then
        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(200),
                () -> assertThat(response.getMessage()).isEqualTo("User update successfully"),
                () -> assertThat(response.getFirstName()).isEqualTo("foobar"),
                () -> assertThat(response.getLastName()).isEqualTo("barfoo")
                );
    }

    @Test
    void deleteUser_should_throws_UserNotFoundException() {
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailFacade = mock(EmailFacade.class);

        when(jwtUtils.extractUsername(anyString())).thenReturn("foo-email");

        //system under test
        var toTest = new LoginAndRegisterFacade(
                appUserRepository,
                passwordEncoder,
                jwtUtils,
                authenticationManager,
                confirmationTokenService,
                emailFacade
        );

        //when
        String request = "foobar";

        Throwable e = catchThrowable(() -> toTest.deleteUser(request));

        //then
        assertAll(
                () -> assertThat(e).isInstanceOf(UsernameNotFoundException.class),
                () -> assertThat(e.getMessage()).isEqualTo("User extracted from token not found.")
        );
    }

    @Test
    void deleteUser_should_throws_BadTokenTypeException() {
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailFacade = mock(EmailFacade.class);

        when(jwtUtils.extractUsername(anyString())).thenReturn("foo-email");
        when(jwtUtils.isRefreshToken(anyString())).thenReturn(true);

        AppUser user = new AppUser();
        user.setFirstName("Foo");
        user.setLastName("Bar");
        user.setEmail("test@foo.com");
        user.setPassword("foobar");
        user.setRole("USER");
        user.setEnabled(true);

        when(appUserRepository.findByEmail(anyString()))
                .thenReturn(Optional.of(user));

        //system under test
        var toTest = new LoginAndRegisterFacade(
                appUserRepository,
                passwordEncoder,
                jwtUtils,
                authenticationManager,
                confirmationTokenService,
                emailFacade
        );

        //when
        String request = "foobar";

        Throwable e = catchThrowable(() -> toTest.deleteUser(request));

        //then
        assertAll(
                () -> assertThat(e).isInstanceOf(BadTokenTypeException.class),
                () -> assertThat(e.getMessage()).isEqualTo("Invalid Token type.")
        );
    }

    @Test
    void deleteUser_should_throws_CredentialsExpiredException() {
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailFacade = mock(EmailFacade.class);

        when(jwtUtils.extractUsername(anyString())).thenReturn("foo-email");

        AppUser user = new AppUser();
        user.setFirstName("Foo");
        user.setLastName("Bar");
        user.setEmail("test@foo.com");
        user.setPassword("foobar");
        user.setRole("USER");
        user.setEnabled(true);

        when(appUserRepository.findByEmail(anyString()))
                .thenReturn(Optional.of(user));

        when(jwtUtils.isRefreshToken(anyString())).thenReturn(false);
        when(jwtUtils.isTokenValid(anyString(), any(UserDetails.class))).thenReturn(false);


        //system under test
        var toTest = new LoginAndRegisterFacade(
                appUserRepository,
                passwordEncoder,
                jwtUtils,
                authenticationManager,
                confirmationTokenService,
                emailFacade
        );

        //when
        String request = "foobar";
        Throwable e = catchThrowable(() -> toTest.deleteUser(request));

        //then
        assertAll(
                () -> assertThat(e).isInstanceOf(CredentialsExpiredException.class),
                () -> assertThat(e.getMessage()).isEqualTo("Token expired.")
        );
    }

    @Test
    void deleteUser_should_returns_accessToken_and_204() throws Exception {
        //given
        var appUserRepository =mock(AppUserRepository.class);
        var passwordEncoder = mock(PasswordEncoder.class);
        var jwtUtils = mock(JWTUtils.class);
        var authenticationManager = mock(AuthenticationManager.class);
        var confirmationTokenService = mock(ConfirmationTokenService.class);
        var emailFacade = mock(EmailFacade.class);

        when(jwtUtils.extractUsername(anyString())).thenReturn("foo-email");

        AppUser user = new AppUser();
        user.setFirstName("Foo");
        user.setLastName("Bar");
        user.setEmail("test@foo.com");
        user.setPassword("foobar");
        user.setRole("USER");
        user.setEnabled(true);

        when(appUserRepository.findByEmail(anyString()))
                .thenReturn(Optional.of(user));
        doNothing().when(appUserRepository).deleteByEmail(anyString());
        doNothing().when(confirmationTokenService).deleteConfirmationToken(any(AppUser.class));

        when(jwtUtils.isRefreshToken(anyString())).thenReturn(false);
        when(jwtUtils.isTokenValid(anyString(), any(UserDetails.class))).thenReturn(true);

        //system under test
        var toTest = new LoginAndRegisterFacade(
                appUserRepository,
                passwordEncoder,
                jwtUtils,
                authenticationManager,
                confirmationTokenService,
                emailFacade
        );

        //when
        String request = "foobar";
        AuthReqRespDTO response = toTest.deleteUser(request);

        //then
        assertAll(
                () -> assertThat(response.getStatusCode()).isEqualTo(204),
                () -> assertThat(response.getMessage()).isEqualTo("Successfully deleted user")
        );
    }
}