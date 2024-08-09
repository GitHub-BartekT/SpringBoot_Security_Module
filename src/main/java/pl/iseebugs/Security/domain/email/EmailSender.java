package pl.iseebugs.Security.domain.email;

public interface EmailSender
{
    void send(String to, String subject, String email);
}
