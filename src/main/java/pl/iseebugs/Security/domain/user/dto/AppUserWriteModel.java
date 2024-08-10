package pl.iseebugs.Security.domain.user.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AppUserWriteModel {
    private Long id;
    private String firstName;
    private String lastName;
    private String email;
    private String password;
    private String role;
    private boolean locked;
    private boolean enabled;
}
