package pl.iseebugs.Security.domain.account.create;

public class RegistrationTokenConflictException extends Exception{
    public RegistrationTokenConflictException() {
        super("Token already confirmed.");
    }
    public RegistrationTokenConflictException(String message) {
        super(message);
    }
}
