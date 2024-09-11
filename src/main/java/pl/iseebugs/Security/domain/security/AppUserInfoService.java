package pl.iseebugs.Security.domain.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.account.EmailNotFoundException;
import pl.iseebugs.Security.domain.user.AppUserFacade;
import pl.iseebugs.Security.domain.user.AppUserNotFoundException;
import pl.iseebugs.Security.domain.user.dto.AppUserReadModel;
import pl.iseebugs.Security.domain.security.projection.AppUserReadModelSecurity;

@Service
class AppUserInfoService implements UserDetailsService {
    AppUserFacade appUserFacade;

    @Autowired
    AppUserInfoService(AppUserFacade appUserFacade){
        this.appUserFacade = appUserFacade;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws BadCredentialsException {
        AppUserReadModelSecurity user;
        try {
            user = findByUsername(username);
        } catch (AppUserNotFoundException | EmailNotFoundException e) {
            throw new RuntimeException(e);
        }
        return getUser(user);
    }

    private AppUserInfoDetails getUser(AppUserReadModelSecurity userReadModel){
        return new AppUserInfoDetails(userReadModel);
    }

    AppUserReadModelSecurity findByUsername(final String email) throws BadCredentialsException, AppUserNotFoundException, EmailNotFoundException {
       AppUserReadModel user = appUserFacade.findByEmail(email);
       return  AppUserReadModelSecurity.builder()
               .firstName(user.firstName())
               .lastName(user.lastName())
               .email(user.email())
               .password(user.password())
               .roles(user.role())
               .enable(user.enabled())
               .build();
    }
}
