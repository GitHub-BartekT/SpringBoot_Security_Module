package pl.iseebugs.appuser;

import pl.iseebugs.appuser.projection.AppUserReadModel;

class AppUserMapper {
    public static AppUserInfoDetails toAppUserInfoDetails(AppUserReadModel user){
        return AppUserInfoDetails.builder()
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .password(user.getPassword())
                .email(user.getEmail())
                .appUserRole(user.getAppUserRole())
                .enabled(user.getEnabled())
                .locked(user.getLocked())
                .build();
    }
}
