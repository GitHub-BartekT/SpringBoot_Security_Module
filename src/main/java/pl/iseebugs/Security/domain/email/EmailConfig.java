package pl.iseebugs.Security.domain.email;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;
import org.thymeleaf.templateresolver.ITemplateResolver;

@Component
public class EmailConfig {

    @Bean(name = "emailTemplateResolver")
    public ITemplateResolver emailTemplateResolver()
    {
        ClassLoaderTemplateResolver templateResolver = new ClassLoaderTemplateResolver();
        templateResolver.setPrefix("templates/");
        templateResolver.setSuffix(".html");
        templateResolver.setTemplateMode(TemplateMode.HTML);
        return templateResolver;
    }

    @Bean(name = "emailTemplateEngine")
    public TemplateEngine emailTemplateEngine(@Qualifier("emailTemplateResolver") ITemplateResolver emailTemplateResolver)
    {
        TemplateEngine templateEngine = new TemplateEngine();
        templateEngine.setTemplateResolver(emailTemplateResolver);
        return templateEngine;
    }
}
