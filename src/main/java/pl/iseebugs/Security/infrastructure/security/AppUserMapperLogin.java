package pl.iseebugs.Security.infrastructure.security;

import pl.iseebugs.Security.domain.user.dto.AppUserReadModel;
import pl.iseebugs.Security.domain.user.dto.AppUserWriteModel;

class AppUserMapperLogin {
    static AppUserInfoDetails fromAppUserReadModelToUserDetails(AppUserReadModel userDetails) {
        return new AppUserInfoDetails(
                userDetails.firstName(),
                userDetails.lastName(),
                userDetails.email(),
                userDetails.password(),
                userDetails.role());
    }

    static AppUserWriteModel fromUserDetailsToAppUserReadModel(AppUserInfoDetails userDetails) {
        return AppUserWriteModel.builder()
                .firstName(userDetails.getFirstName())
                .lastName(userDetails.getLastName())
                .email(userDetails.getUsername())
                .password(userDetails.getPassword())
                .role(userDetails.getAuthorities().toString())
                .enabled(userDetails.isEnabled())
                .locked(!userDetails.isAccountNonLocked())
                .build();
    }
}
