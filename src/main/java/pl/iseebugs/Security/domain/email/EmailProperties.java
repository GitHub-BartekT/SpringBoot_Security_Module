package pl.iseebugs.Security.domain.email;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

@Configuration
@ConfigurationProperties(prefix = "email")
@Getter
@Setter
public class EmailProperties {

    private Map<String, EmailTemplate> templates;
    private Sender sender;

    @Getter
    @Setter
    public static class EmailTemplate {
        private String subject;
        private String template;
        private String welcomeText;
        private String text1;
        private String text2;
    }

    @Getter
    @Setter
    public static class Sender {
        private String name;
        private String email;
    }
}