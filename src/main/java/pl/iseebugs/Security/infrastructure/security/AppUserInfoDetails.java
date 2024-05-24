package pl.iseebugs.Security.infrastructure.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import pl.iseebugs.Security.domain.user.AppUser;
import pl.iseebugs.Security.infrastructure.security.projection.AppUserReadModel;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

class AppUserInfoDetails implements UserDetails {
    private final String firstName;
    private final String lastName;
    private final String email;
    private final String password;
    private final String role;
    private Boolean locked = false;
    private Boolean enabled = true;

    public AppUserInfoDetails(
            String firstName,
            String lastName,
            String email,
            String password,
            String role
            ){
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
        this.password = password;
        this.role = role;
    }

    public AppUserInfoDetails(AppUserReadModel userReadModel){
        this.firstName = userReadModel.getFirstName();
        this.lastName = userReadModel.getLastName();
        this.email = userReadModel.getEmail();
        this.password = userReadModel.getPassword();
        this.role = userReadModel.getRoles();
    }


    /*Arrays.stream(userReadModel.getRoles().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList())*/
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role));
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !locked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    String getFirstName() {
        return firstName;
    }

    String getLastName() {
        return lastName;
    }

    AppUser toNewAppUser(){
            return AppUser.builder()
                    .firstName(this.firstName)
                    .lastName(this.lastName)
                    .email(this.email)
                    .password(this.password)
                    .role(this.role)
                    .locked(locked)
                    .enabled(enabled)
                    .build();
        }

}
