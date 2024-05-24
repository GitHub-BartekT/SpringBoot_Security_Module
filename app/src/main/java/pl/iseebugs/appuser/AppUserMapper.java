package pl.iseebugs.appuser;

import pl.iseebugs.appuser.projection.AppUserReadModel;
import pl.iseebugs.appuser.projection.AppUserWriteModel;

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

    public static AppUser toAppUserFromWriteModel(AppUserWriteModel userWriteModel){
        return new AppUser(
                userWriteModel.getFirstName(),
                userWriteModel.getLastName(),
                userWriteModel.getEmail(),
                userWriteModel.getPassword(),
                userWriteModel.getAppUserRole());
    }

    public static AppUserReadModel toAppUserReadModel(AppUser user){
        return AppUserReadModel.builder()
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
