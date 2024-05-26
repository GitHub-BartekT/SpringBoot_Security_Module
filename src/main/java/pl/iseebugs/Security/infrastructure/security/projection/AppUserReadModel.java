package pl.iseebugs.Security.infrastructure.security.projection;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@AllArgsConstructor
public class AppUserReadModel {
    private final String firstName;
    private final String lastName;
    private final String email;
    private final String password;
    private final String roles;
    private final Boolean enable;
}
