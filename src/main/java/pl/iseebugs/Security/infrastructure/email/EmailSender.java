package pl.iseebugs.Security.infrastructure.email;

public interface EmailSender {
    void send(String to, String subject, String email);
}
