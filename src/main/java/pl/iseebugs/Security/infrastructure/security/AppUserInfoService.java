package pl.iseebugs.Security.infrastructure.security;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.user.AppUserRepository;
import pl.iseebugs.Security.infrastructure.security.projection.AppUserReadModelSecurity;

@Service
class AppUserInfoService implements UserDetailsService {
    private static final String USER_NOT_FOUND = "User not found.";

    AppUserRepository appUserRepository;

    AppUserInfoService(AppUserRepository appUserRepository){
        this.appUserRepository = appUserRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws BadCredentialsException {
        AppUserReadModelSecurity user = findByUsername(username);
        return getUser(user);
    }

    private AppUserInfoDetails getUser(AppUserReadModelSecurity userReadModel){
        return new AppUserInfoDetails(userReadModel);
    }

    AppUserReadModelSecurity findByUsername(final String email) throws BadCredentialsException {
        return appUserRepository.findByEmail(email)
                .map(user -> AppUserReadModelSecurity.builder()
                        .firstName(user.getFirstName())
                        .lastName(user.getLastName())
                        .email(user.getEmail())
                        .password(user.getPassword())
                        .roles(user.getRole())
                        .enable(user.getEnabled())
                        .build())
                .orElseThrow(() -> new UsernameNotFoundException(USER_NOT_FOUND));
    }
}
