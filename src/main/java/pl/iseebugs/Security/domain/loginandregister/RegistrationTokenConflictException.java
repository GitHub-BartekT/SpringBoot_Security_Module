package pl.iseebugs.Security.domain.loginandregister;

public class RegistrationTokenConflictException extends Exception{
    public RegistrationTokenConflictException() {
        super("Token already confirmed.");
    }
    public RegistrationTokenConflictException(String message) {
        super(message);
    }

    public static class BadTokenTypeException extends Exception{
        public BadTokenTypeException() {
            super("Invalid Token type.");
        }
        public BadTokenTypeException(String message) {
            super(message);
        }
    }
}
