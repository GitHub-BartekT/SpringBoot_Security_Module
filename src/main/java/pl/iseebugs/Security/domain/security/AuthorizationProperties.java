package pl.iseebugs.Security.domain.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Getter
@Setter
@Configuration
@ConfigurationProperties(value = "auth")
public class AuthorizationProperties{
        private String secret;
        private int expirationRefreshTokenTime;
        private int expirationAccessTokenTime;
        private int expirationConfirmationTokenTime;
        private int expirationDeleteTokenTime;
}
