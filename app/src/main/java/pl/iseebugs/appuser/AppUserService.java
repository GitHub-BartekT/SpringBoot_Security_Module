package pl.iseebugs.appuser;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import pl.iseebugs.appuser.projection.AppUserReadModel;

@Service
class AppUserService implements UserDetailsService {
    private final static String USER_NOT_FOUND_MSG =
            "user with email %s not found";

    AppUserRepository appUserRepository;

    AppUserService(AppUserRepository appUserRepository){
        this.appUserRepository = appUserRepository;
    }

    @Override
    public UserDetails loadUserByUsername(final String email) throws UsernameNotFoundException {
        AppUserReadModel user = findBUsername(email);
        return AppUserMapper.toAppUserInfoDetails(user);
    }

    private AppUserReadModel findBUsername(String email) throws UsernameNotFoundException{
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
