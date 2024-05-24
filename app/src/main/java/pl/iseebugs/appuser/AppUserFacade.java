package pl.iseebugs.appuser;

import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import pl.iseebugs.appuser.projection.AppUserReadModel;

@AllArgsConstructor
@Service
class AppUserFacade implements UserDetailsService {
    private final static String USER_NOT_FOUND_MSG =
            "user with email %s not found";

    AppUserRepository appUserRepository;

    @Override
    public UserDetails loadUserByUsername(final String email) throws UsernameNotFoundException {
        AppUserReadModel user = findByEmail(email);
        return AppUserMapper.toAppUserInfoDetails(user);
    }

    private AppUserReadModel findByEmail(String email) throws UsernameNotFoundException{
        return  appUserRepository
                .findByEmail(email)
                .map(appUser -> AppUserReadModel.builder()
                        .firstName(appUser.getFirstName())
                        .lastName(appUser.getLastName())
                        .email(appUser.getEmail())
                        .password(appUser.getPassword())
                        .appUserRole(appUser.getAppUserRole())
                        .locked(appUser.getLocked())
                        .enabled(appUser.getEnabled())
                        .build()
                )
                .orElseThrow(() ->
                        new UsernameNotFoundException(String.format(USER_NOT_FOUND_MSG,email)));
    }
}
