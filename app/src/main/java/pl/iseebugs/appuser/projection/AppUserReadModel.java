package pl.iseebugs.appuser.projection;

import lombok.Builder;
import lombok.Getter;
import pl.iseebugs.appuser.AppUserRole;

@Getter
@Builder
public class AppUserReadModel {
    private String firstName;
    private String lastName;
    private String email;
    private String password;
    private AppUserRole appUserRole;
    private Boolean locked;
    private Boolean enabled;
}
