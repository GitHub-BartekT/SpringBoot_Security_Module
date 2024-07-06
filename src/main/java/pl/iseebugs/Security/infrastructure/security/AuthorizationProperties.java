package pl.iseebugs.Security.infrastructure.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(value = "auth")
public record AuthorizationProperties(
        String secret
) {
}

