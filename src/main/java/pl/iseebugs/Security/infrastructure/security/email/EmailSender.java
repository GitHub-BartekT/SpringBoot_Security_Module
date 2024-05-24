package pl.iseebugs.Security.infrastructure.security.email;

public interface EmailSender {
    void send(String to, String email);
}
