package pl.iseebugs.Security.domain.email;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import pl.iseebugs.Security.domain.account.lifecycle.dto.AppUserDto;

@Service
public class EmailFacade implements EmailSender{

    private final static Logger LOGGER = LoggerFactory
            .getLogger(EmailFacade.class);

    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;
    private final EmailProperties emailProperties;

    @Autowired
    public EmailFacade(final JavaMailSender mailSender, final TemplateEngine templateEngine, final EmailProperties emailProperties) {
        this.mailSender = mailSender;
        this.templateEngine = templateEngine;
        this.emailProperties = emailProperties;
    }

    public void sendTemplateEmail(EmailType type, AppUserDto userData, String link) throws InvalidEmailTypeException {
        EmailProperties.EmailTemplate template =
                emailProperties.getTemplates().get(type.toString());

        if (template == null){
            throw new InvalidEmailTypeException("Invalid email type: " + type);
        }
        String firstName = userData.getFirstName() == null ? "new user" : userData.getFirstName();

        Context context = new Context();
        String welcomeText = template.getWelcomeText().replace("${name}", firstName);
        context.setVariable("welcomeText", welcomeText);
        context.setVariable("text1", template.getText1());
        context.setVariable("link", link);
        context.setVariable("text2", template.getText2());

        String email = this.templateEngine.process(template.getTemplate(), context);

        send(userData.getEmail(), template.getSubject(), email);
    }

    @Override
    @Async
    public void send(final String to, final String subject, final String email) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper =
                    new MimeMessageHelper(mimeMessage, "utf-8");
            helper.setFrom(emailProperties.getSender().getEmail());
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(email, true);
            mailSender.send(mimeMessage);
            LOGGER.info("Mail sent to: " + to);
        } catch (MessagingException e){
            LOGGER.error("Failed to send email.", e);
            throw new IllegalStateException("Failed to send email");
        }
    }
}
