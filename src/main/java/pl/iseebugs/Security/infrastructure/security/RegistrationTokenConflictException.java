package pl.iseebugs.Security.infrastructure.security;

public class RegistrationTokenConflictException extends Exception{
    public RegistrationTokenConflictException() {
        super("Token already confirmed.");
    }
    public RegistrationTokenConflictException(String message) {
        super(message);
    }
}
