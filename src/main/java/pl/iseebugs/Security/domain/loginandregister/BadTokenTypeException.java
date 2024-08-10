package pl.iseebugs.Security.domain.loginandregister;

public class BadTokenTypeException extends Exception{
    public BadTokenTypeException() {
        super("Invalid Token type.");
    }
    public BadTokenTypeException(String message) {
        super(message);
    }
}
