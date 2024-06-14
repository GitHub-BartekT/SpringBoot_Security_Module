package pl.iseebugs.Security.infrastructure.email;

public class InvalidEmailTypeException extends Exception{
    public InvalidEmailTypeException() {
        super("Invalid email type.");
    }
    public InvalidEmailTypeException(String message) {
        super(message);
    }
}
