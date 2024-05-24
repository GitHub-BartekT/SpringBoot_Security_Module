package pl.iseebugs.Security.domain.user;

public class AppUserNotFoundException extends Exception {
    public AppUserNotFoundException() {
        super("User Cost not found.");
    }

    public AppUserNotFoundException (String message) {
        super(message);
    }
}
