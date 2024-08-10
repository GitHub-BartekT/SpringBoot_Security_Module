package pl.iseebugs.Security.domain.account;

public class BadTokenTypeException extends Exception{
    public BadTokenTypeException() {
        super("Invalid Token type.");
    }
    public BadTokenTypeException(String message) {
        super(message);
    }
}
