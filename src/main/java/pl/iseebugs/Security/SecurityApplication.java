package pl.iseebugs.Security;

import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
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
