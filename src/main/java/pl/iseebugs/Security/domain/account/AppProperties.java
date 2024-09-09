package pl.iseebugs.Security.domain.account;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(value = "app")
public record AppProperties(
        String uri,
        int port
) {
}

