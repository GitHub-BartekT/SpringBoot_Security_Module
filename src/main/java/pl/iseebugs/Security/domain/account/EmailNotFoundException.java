package pl.iseebugs.Security.domain.account;

public class EmailNotFoundException extends Exception{
    public EmailNotFoundException() {
        super("Email not found.");
    }
    public EmailNotFoundException(String message) {
        super(message);
    }
}
