package pl.iseebugs.appuser;

import jakarta.persistence.*;
import lombok.EqualsAndHashCode;

@EqualsAndHashCode
@Entity
class AppUser{
    @SequenceGenerator(
            name = "app_user_sequence",
            sequenceName = "app_user_sequence",
            allocationSize = 1
    )
    @Id
    @GeneratedValue(
            strategy = GenerationType.SEQUENCE,
            generator = "app_user_sequence"
    )
    private Long id;
    private String firstName;
    private String lastName;
    private String email;
    private String password;
    @Enumerated(EnumType.STRING)
    private AppUserRole appUserRole;
    private Boolean locked = false;
    private Boolean enabled = false;

    protected AppUser(){}

    public AppUser(final String firstName,
                   final String lastName,
                   final String email,
                   final String password,
                   final AppUserRole appUserRole) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
        this.password = password;
        this.appUserRole = appUserRole;
    }

    String getFirstName() {
        return firstName;
    }

    String getLastName() {
        return lastName;
    }

    String getEmail() {
        return email;
    }

    String getPassword() {
        return password;
    }

    AppUserRole getAppUserRole() {
        return appUserRole;
    }

    Boolean getLocked() {
        return locked;
    }

    Boolean getEnabled() {
        return enabled;
    }
}
