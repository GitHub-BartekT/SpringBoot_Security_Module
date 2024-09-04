package pl.iseebugs.Security.domain.account;

import org.springframework.stereotype.Component;
import pl.iseebugs.Security.domain.security.AppProperties;

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
}