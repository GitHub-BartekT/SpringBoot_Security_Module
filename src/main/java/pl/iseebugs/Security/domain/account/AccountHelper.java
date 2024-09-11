package pl.iseebugs.Security.domain.account;

import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class AccountHelper {

    private final AppProperties appProperties;

    AccountHelper(final AppProperties appProperties) {
        this.appProperties = appProperties;
    }

    public String createUrl(final String endpoint, final String token) {
        return appProperties.uri() + ":" +
                appProperties.port() +
                endpoint +
                token;
    }

    public static String getUUID() {
        return UUID.randomUUID().toString();
    }
}
