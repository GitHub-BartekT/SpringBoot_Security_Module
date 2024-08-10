package pl.iseebugs.Security.domain.email;

public interface EmailSender
{
    void send(String to, String subject, String email);

    class EmailConflictException extends Exception{
        public EmailConflictException() {
            super("The email address already exists.");
        }
        public EmailConflictException(String message) {
            super(message);
        }
    }
}
