package pl.iseebugs.Security.domain.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.java.Log;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import pl.iseebugs.Security.domain.security.projection.LoginTokenDto;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;

@Component
@Log
class JWTUtils {

    private final SecretKey Key;
    private static long EXPIRATION_REFRESH_TOKEN_TIME;
    private static long EXPIRATION_ACCESS_TOKEN_TIME;

    JWTUtils(final AuthorizationProperties authorizationProperties){
        EXPIRATION_REFRESH_TOKEN_TIME = authorizationProperties.getExpirationRefreshTokenTime();
        EXPIRATION_ACCESS_TOKEN_TIME = authorizationProperties.getExpirationAccessTokenTime();
        String secretString = authorizationProperties.getSecret();
        byte[] keyBytes = Base64.getDecoder().decode(secretString.getBytes(StandardCharsets.UTF_8));
        this.Key = new SecretKeySpec(keyBytes,"HmacSHA256");
    }

    public LoginTokenDto generateAccessToken(UserDetails userDetails){
        return generateToken(userDetails, Token.ACCESS);
    }

    public LoginTokenDto generateRefreshToken(UserDetails userDetails){
     return generateToken(userDetails, Token.REFRESH);
    }

    private LoginTokenDto generateToken(UserDetails userDetails, Token tokenType){
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("type", tokenType);
        long tokenTime = tokenType.equals(Token.ACCESS) ? EXPIRATION_ACCESS_TOKEN_TIME : EXPIRATION_REFRESH_TOKEN_TIME;

        log.info("Created " + tokenType + " token for user with email: " + userDetails.getUsername());

        Date expiresAt = new Date(System.currentTimeMillis() + tokenTime);
        String token = Jwts.builder()
                .claims(claims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(expiresAt)
                .signWith(Key)
                .compact();

        return LoginTokenDto.builder()
                .token(token)
                .expiresAt(expiresAt).build();
    }

    public String extractUsername(String token){
        return extractClaims(token, Claims::getSubject);
    }

    public boolean isRefreshToken(String token) {
        return Token.REFRESH.name().equals(extractClaims(token, claims -> claims.get("type")));
    }

    public boolean isAccessToken(String token) {
        return Token.ACCESS.name().equals(extractClaims(token, claims -> claims.get("type")));
    }

    private <T> T extractClaims(String token, Function<Claims, T> claimsTFunction){
        return claimsTFunction.apply(Jwts.parser().verifyWith(Key).build().parseSignedClaims(token).getPayload());
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) &&! isTokenExpired(token));
    }

    public boolean isTokenValid(String token, String email){
        final String username = extractUsername(token);
        return (username.equals(email) &&! isTokenExpired(token));
    }

    public boolean isTokenExpired(String token){
        return extractClaims(token, Claims::getExpiration).before(new Date());
    }

    public Date extractExpiresAt(String token){
      return extractClaims(token, Claims::getExpiration);
    }
}
