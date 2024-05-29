package pl.iseebugs.Security.infrastructure.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.java.Log;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

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
    private static final long EXPIRATION_REFRESH_TIME = 86400000; //24 hours or 86400 000 milliseconds
    private static final long EXPIRATION_ACCESS_TIME = 3600000; //60 minutes or 3600 000 milliseconds

    JWTUtils(){
        String secreteString = "4564654654654654564879956465JHKJ456497891233";
        byte[] keyBytes = Base64.getDecoder().decode(secreteString.getBytes(StandardCharsets.UTF_8));
        this.Key = new SecretKeySpec(keyBytes,"HmacSHA256");
    }

    public String generateAccessToken(UserDetails userDetails){
        return generateToken(userDetails, Token.ACCESS);
    }

    public String generateRefreshToken(UserDetails userDetails){
     return generateToken(userDetails, Token.REFRESH);
    }

    private String generateToken(UserDetails userDetails, Token tokenType){
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("type", tokenType);
        long tokenTime = tokenType.equals(Token.ACCESS) ? EXPIRATION_ACCESS_TIME : EXPIRATION_REFRESH_TIME;

        log.info("Created " + tokenType + " token for user with email: " + userDetails.getUsername());

        return Jwts.builder()
                .claims(claims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + tokenTime))
                .signWith(Key)
                .compact();
    }

    public String extractUsername(String token){
        return extractClaims(token, Claims::getSubject);
    }

    public boolean isRefreshToken(String token) {
        return Token.REFRESH.name().equals(extractClaims(token, claims -> claims.get("type")));
    }

    private <T> T extractClaims(String token, Function<Claims, T> claimsTFunction){
        return claimsTFunction.apply(Jwts.parser().verifyWith(Key).build().parseSignedClaims(token).getPayload());
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) &&! isTokenExpired(token));
    }

    public boolean isTokenExpired(String token){
        return extractClaims(token, Claims::getExpiration).before(new Date());
    }
}
