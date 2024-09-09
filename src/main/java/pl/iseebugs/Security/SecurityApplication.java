package pl.iseebugs.Security;

import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import pl.iseebugs.Security.domain.email.EmailProperties;
import pl.iseebugs.Security.domain.account.AppProperties;
import pl.iseebugs.Security.domain.security.AuthorizationProperties;

@SpringBootApplication
@EnableConfigurationProperties({EmailProperties.class, AuthorizationProperties.class, AppProperties.class})
public class SecurityApplication {

	public static void main(String[] args) {
		Dotenv dotenv = Dotenv.configure()
				.ignoreIfMissing()
				.load();

		setDefaultProperty(dotenv, "POSTGRES_USER", "postgres");
		setDefaultProperty(dotenv, "POSTGRES_PASSWORD", "pass");

		dotenv.entries().forEach(entry -> System.setProperty(entry.getKey(), entry.getValue()));
		SpringApplication.run(SecurityApplication.class, args);
	}

	private static void setDefaultProperty(Dotenv dotenv, String key, String defaultValue) {
		String value = dotenv.get(key, defaultValue);
		System.setProperty(key, value);
	}

}
