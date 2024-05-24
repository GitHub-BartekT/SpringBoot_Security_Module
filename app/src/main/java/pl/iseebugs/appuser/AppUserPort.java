package pl.iseebugs.appuser;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import pl.iseebugs.appuser.projection.AppUserReadModel;
import pl.iseebugs.appuser.projection.AppUserWriteModel;

interface AppUserPort {
    public UserDetails loadUserByUsername(final String email) throws UsernameNotFoundException;
    AppUserReadModel save(AppUserWriteModel appUserWriteModel);
    boolean exists(String email);
    boolean delete(String email);
}
