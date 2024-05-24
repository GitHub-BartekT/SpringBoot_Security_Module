package pl.iseebugs.Security.infrastructure.security.projection;

import lombok.AllArgsConstructor;
import lombok.Builder;

@Builder
@AllArgsConstructor
public class AppUserReadModel {

    private final String firstName;
    private final String lastName;
    private final String email;
    private final String password;
    private final String roles;


    public String getFirstName() {
        return firstName;
    }

    public String getPassword() {
        return password;
    }

    public String getRoles() {
        return roles;
    }

    public String getLastName() {
        return lastName;
    }

    public  String getEmail() {
        return email;
    }
}
