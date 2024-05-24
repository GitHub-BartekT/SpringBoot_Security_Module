package pl.iseebugs.Security.infrastructure.security;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.user.AppUserRepository;
import pl.iseebugs.Security.infrastructure.security.projection.AppUserReadModel;

@Service
class AppUserInfoService implements UserDetailsService {
    private static final String USER_NOT_FOUND = "User not found";

    AppUserRepository appUserRepository;

    AppUserInfoService(AppUserRepository appUserRepository){
        this.appUserRepository = appUserRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws BadCredentialsException {
        AppUserReadModel user = findByUsername(username);
        return getUser(user);
    }

    private AppUserInfoDetails getUser(AppUserReadModel userReadModel){
        return new AppUserInfoDetails(userReadModel);
    }


    AppUserReadModel findByUsername(final String email) throws BadCredentialsException {
        return appUserRepository.findByEmail(email)
                .map(user -> AppUserReadModel.builder()
                        .firstName(user.getFirstName())
                        .lastName(user.getLastName())
                        .email(user.getEmail())
                        .password(user.getPassword())
                        .roles(user.getRole())
                        .build())
                .orElseThrow(() -> new BadCredentialsException(USER_NOT_FOUND));
    }
}
