package pl.iseebugs.Security.domain.email;

public class InvalidEmailTypeException extends Exception{
    public InvalidEmailTypeException() {
        super("Invalid email type.");
    }
    public InvalidEmailTypeException(String message) {
        super(message);
    }
}
