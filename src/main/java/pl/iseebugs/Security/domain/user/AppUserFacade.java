package pl.iseebugs.Security.domain.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.user.dto.AppUserReadModel;
import pl.iseebugs.Security.domain.user.dto.AppUserWriteModel;

@Service
public class AppUserFacade {

    private final AppUserRepository appUserRepository;

    @Autowired
    public AppUserFacade(AppUserRepository appUserRepository) {
        this.appUserRepository = appUserRepository;
    }

    public boolean existsByEmail(String email){
        return appUserRepository.existsByEmail(email);
    }

    public AppUserReadModel findUserById(Long id) throws AppUserNotFoundException {
        AppUser user = appUserRepository.findById(id).orElseThrow(AppUserNotFoundException::new);
        return AppUserMapper.toAppUserReadModel(user);
    }

    public AppUserReadModel findByEmail(String email) throws AppUserNotFoundException {
        AppUser user = appUserRepository.findByEmail(email).orElseThrow(AppUserNotFoundException::new);
        return AppUserMapper.toAppUserReadModel(user);
    }
    public AppUserReadModel update(AppUserWriteModel appUser) throws AppUserNotFoundException {
        AppUser toUpdate = AppUserMapper.toAppUser(appUser);
        AppUser updated = appUserRepository.save(toUpdate);
        return AppUserMapper.toAppUserReadModel(updated);
    }

    public void enableAppUser(Long id) throws AppUserNotFoundException {
        appUserRepository.findById(id).orElseThrow(AppUserNotFoundException::new);

        appUserRepository.enableAppUser(id);
    }

    public AppUserReadModel create(AppUserWriteModel appUser) throws AppUserNotFoundException {
        if(appUser.getId() != null){
            throw new IllegalArgumentException("Id could be present.");
        }
        if(appUserRepository.existsByEmail(appUser.getEmail())){
            throw new IllegalArgumentException("User already exists.");
        }
        AppUser toCreate = AppUserMapper.toAppUser(appUser);
        AppUser created = appUserRepository.save(toCreate);
        return AppUserMapper.toAppUserReadModel(created);
    }

}
