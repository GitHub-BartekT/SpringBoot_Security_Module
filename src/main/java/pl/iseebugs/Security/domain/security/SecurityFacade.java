package pl.iseebugs.Security.domain.security;

import lombok.AllArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.account.BadTokenTypeException;
import pl.iseebugs.Security.domain.security.projection.LoginTokenDto;
import pl.iseebugs.Security.domain.user.dto.AppUserReadModel;


@AllArgsConstructor
@Service
@Log
public class SecurityFacade {

    private final PasswordEncoder passwordEncoder;
    private final JWTUtils jwtUtils;
    private final AuthenticationManager authenticationManager;

    public String passwordEncode(CharSequence rawPassword) {
        return passwordEncoder.encode(rawPassword);
    }

    public String extractUsername(String token) {
        return jwtUtils.extractUsername(token);
    }

    public void isAccessToken(String accessToken) throws BadTokenTypeException {
        if (jwtUtils.isAccessToken(accessToken)) {
            return;
        }
        log.info("The provided token is not an access token.");
        throw new BadTokenTypeException();
    }

    public void isRefreshToken(String refreshToken) throws BadTokenTypeException {
        if (jwtUtils.isRefreshToken(refreshToken)) {
            return;
        }
        log.info("The provided token is not an refresh token.");
        throw new BadTokenTypeException();
    }

    public void isTokenExpired(String accessToken) {
        String userEmail = extractUsername(accessToken);
        if (jwtUtils.isTokenExpired(accessToken)) {
            log.info("User with email: " + userEmail + " used an expired token.");
            throw new CredentialsExpiredException("Token expired.");
        }
    }

    public LoginTokenDto generateAccessToken(AppUserReadModel appUserReadModel){
        UserDetails userToJWT = AppUserMapperLogin.fromAppUserReadModelToUserDetails(appUserReadModel);
        return jwtUtils.generateAccessToken(userToJWT);
    }

    public LoginTokenDto generateRefreshToken(AppUserReadModel appUserReadModel){
        UserDetails userToJWT = AppUserMapperLogin.fromAppUserReadModelToUserDetails(appUserReadModel);
        return jwtUtils.generateRefreshToken(userToJWT);
    }

    public void authenticateByAuthenticationManager (String email, String password){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        email,
                        password));
    }

    public boolean isTokenValid(String token, String email){
        return jwtUtils.isTokenValid(token, email);
    }
}
