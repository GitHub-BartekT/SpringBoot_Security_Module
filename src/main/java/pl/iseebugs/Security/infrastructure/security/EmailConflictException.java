package pl.iseebugs.Security.infrastructure.security;

public class EmailConflictException extends Exception{
    public EmailConflictException() {
        super("The email address already exists.");
    }
    public EmailConflictException(String message) {
        super(message);
    }
}
