package pl.iseebugs.Security.infrastructure.security;

public class TokenNotFoundException extends Exception{
    public TokenNotFoundException() {
        super("Token not found.");
    }
    public TokenNotFoundException(String message) {
        super(message);
    }
}
