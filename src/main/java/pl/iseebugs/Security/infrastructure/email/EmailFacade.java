package pl.iseebugs.Security.infrastructure.email;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import pl.iseebugs.Security.infrastructure.security.projection.AuthReqRespDTO;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

@Service
public class EmailFacade implements EmailSender{

    private final static Logger LOGGER = LoggerFactory
            .getLogger(EmailFacade.class);

    @Value("${spring.mail.mailer}")
    private String mailer;
    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;


    public EmailFacade(final JavaMailSender mailSender, final TemplateEngine templateEngine) {
        this.mailSender = mailSender;
        this.templateEngine = templateEngine;
    }

    public void sendActivationEmail(AuthReqRespDTO userData, String link) {
        String mail = generateMailHtml(userData.getFirstName(), "activationEmail", link);
        send(userData.getEmail(), "Confirm your email.", mail);
    }

    @Override
    @Async
    public void send(final String to, final String subject, final String email) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper =
                    new MimeMessageHelper(mimeMessage, "utf-8");
            helper.setText(email, true);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setFrom(mailer);
            mailSender.send(mimeMessage);
        } catch (MessagingException e){
            LOGGER.error("Failed to send email.", e);
            throw new IllegalStateException("Failed to send email");
        }
    }

    private String generateMailHtml(String username, String template, String link)
    {
        Map<String, Object> variables = new HashMap<>();
        variables.put("name", username);
        variables.put("link", link);
        String output = this.templateEngine.process(template, new Context(Locale.getDefault(), variables));
        return output;
    }
}
