package pl.iseebugs.Security.domain.security;

import lombok.extern.java.Log;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.account.BadTokenTypeException;
import pl.iseebugs.Security.domain.security.projection.LoginTokenDto;
import pl.iseebugs.Security.domain.user.dto.AppUserReadModel;

import java.util.Date;


@Log
@Service
public class SecurityFacade {

    private final PasswordEncoder passwordEncoder;
    private final JWTUtils jwtUtils;
    private final AuthenticationManager authenticationManager;

    @Autowired
    public SecurityFacade(
        PasswordEncoder passwordEncoder, JWTUtils jwtUtils, AuthenticationManager authenticationManager
    ){
        this.passwordEncoder = passwordEncoder;
        this.jwtUtils = jwtUtils;
        this.authenticationManager = authenticationManager;
    }

    public String passwordEncode(CharSequence rawPassword) {
        return passwordEncoder.encode(rawPassword);
    }

    public String extractUsername(String token) {
        return jwtUtils.extractUsername(token);
    }

    public Date extractExpiresAt(String token) {
        return jwtUtils.extractExpiresAt(token);
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
}
