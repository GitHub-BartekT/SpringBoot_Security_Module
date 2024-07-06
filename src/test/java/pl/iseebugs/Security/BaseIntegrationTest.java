package pl.iseebugs.Security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.icegreen.greenmail.util.GreenMail;
import com.icegreen.greenmail.util.ServerSetup;
import jakarta.annotation.PostConstruct;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;

@SpringBootTest(classes = SecurityApplication.class)
@ActiveProfiles("test")
@AutoConfigureMockMvc
@Testcontainers
public abstract class BaseIntegrationTest {

    public static final String WIRE_MOCK_HOST = "http://localhost:8080/";

    @Autowired
    public MockMvc mockMvc;


    @Autowired
    public ObjectMapper objectMapper;

    @Container
    public static final PostgreSQLContainer<?> postgresqlContainer
            = new PostgreSQLContainer<>(DockerImageName.parse("postgres:latest"))
            .withDatabaseName("test")
            .withUsername("test")
            .withPassword("test");

    @RegisterExtension
    public static WireMockExtension wireMockServer = WireMockExtension.newInstance()
            .options(wireMockConfig().dynamicPort())
            .build();

    private GreenMail greenMail;

    @PostConstruct
    public void setup() {
        System.setProperty("DB_URL", postgresqlContainer.getJdbcUrl());
        System.setProperty("DB_USERNAME", postgresqlContainer.getUsername());
        System.setProperty("DB_PASSWORD", postgresqlContainer.getPassword());
        System.setProperty("wiremock.server.port", String.valueOf(wireMockServer.getPort()));
    }

    @BeforeEach
    public void setUpMailServer() {
        ServerSetup setup = new ServerSetup(1025, "localhost", ServerSetup.PROTOCOL_SMTP);
        greenMail = new GreenMail(setup);
        greenMail.start();

        System.setProperty("spring.mail.host", "localhost");
        System.setProperty("spring.mail.port", "1025");
        System.setProperty("spring.mail.username", "");
        System.setProperty("spring.mail.password", "");
        System.setProperty("spring.mail.properties.mail.smtp.auth", "false");
        System.setProperty("spring.mail.properties.mail.smtp.starttls.enable", "true");
        System.setProperty("spring.mail.properties.mail.smtp.connectiontimeout", "5000");
        System.setProperty("spring.mail.properties.mail.smtp.timeout", "3000");
        System.setProperty("spring.mail.properties.mail.smtp.writetimeout", "5000");
    }

    @AfterEach
    public void tearDownMailServer() {
        if (greenMail != null) {
            greenMail.stop();
        }
    }
}
