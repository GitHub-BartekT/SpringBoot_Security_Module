package pl.iseebugs.Security.domain.security.projection;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@AllArgsConstructor
@Builder
public class RegisterResultReadModel {
    String firstName;
    String lastName;
    String email;
    String role;
    boolean created;
}
