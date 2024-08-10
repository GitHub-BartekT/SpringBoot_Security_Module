package pl.iseebugs.Security.domain.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(value = "app")
public record AppProperties(
        String uri,
        int port
) {
}

