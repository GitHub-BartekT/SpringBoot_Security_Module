package pl.iseebugs.Security.infrastructure.security;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import pl.iseebugs.Security.domain.user.AppUser;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

class AppUserMapper {
    static AppUserInfoDetails fromEntityToUserDetails(AppUser userDetails){
        return new AppUserInfoDetails(
                userDetails.getFirstName(),
                userDetails.getLastName(),
                userDetails.getEmail(),
                userDetails.getPassword(),
                userDetails.getRole());
    }
}
