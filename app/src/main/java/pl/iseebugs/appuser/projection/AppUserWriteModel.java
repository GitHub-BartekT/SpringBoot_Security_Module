package pl.iseebugs.appuser.projection;

import lombok.Data;
import pl.iseebugs.appuser.AppUserRole;

@Data
public class AppUserWriteModel {
    private String firstName;
    private String lastName;
    private String email;
    private String password;
    private AppUserRole appUserRole;
    private Boolean locked;
    private Boolean enabled;
}
