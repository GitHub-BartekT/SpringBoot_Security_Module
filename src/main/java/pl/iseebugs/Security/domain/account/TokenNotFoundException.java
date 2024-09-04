package pl.iseebugs.Security.domain.account;

public class TokenNotFoundException extends Exception{
    public TokenNotFoundException() {
        super("Token not found.");
    }
    public TokenNotFoundException(String message) {
        super(message);
    }
}
