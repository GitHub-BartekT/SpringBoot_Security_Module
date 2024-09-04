package pl.iseebugs.Security.domain.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.account.EmailNotFoundException;
import pl.iseebugs.Security.domain.user.dto.AppUserReadModel;
import pl.iseebugs.Security.domain.user.dto.AppUserWriteModel;

@Service
public class AppUserFacade {

    private final AppUserRepository appUserRepository;

    @Autowired
    public AppUserFacade(AppUserRepository appUserRepository) {
        this.appUserRepository = appUserRepository;
    }

    public boolean existsByEmail(String email) {
        return appUserRepository.existsByEmail(email);
    }

    public AppUserReadModel findUserById(Long id) throws AppUserNotFoundException {
        AppUser user = appUserRepository.findById(id).orElseThrow(AppUserNotFoundException::new);
        return AppUserMapper.toAppUserReadModel(user);
    }

    public AppUserReadModel findByEmail(String email) throws UsernameNotFoundException, EmailNotFoundException {
        AppUser user = appUserRepository.findByEmail(email).orElseThrow(EmailNotFoundException::new);
        return AppUserMapper.toAppUserReadModel(user);
    }

    public AppUserReadModel updatePersonalData(AppUserWriteModel appUser) throws AppUserNotFoundException, EmailNotFoundException {
        if (!existsByEmail(appUser.getEmail())) {
            throw new AppUserNotFoundException();
        }

        AppUser toUpdate = appUserRepository
                .findByEmail(appUser.getEmail())
                .orElseThrow(AppUserNotFoundException::new);

        if (appUser.getFirstName() != null && !appUser.getFirstName().isBlank()) {
            toUpdate.setFirstName(appUser.getFirstName());
        }

        if (appUser.getLastName() != null && !appUser.getLastName().isBlank()) {
            toUpdate.setLastName(appUser.getLastName());
        }
        AppUser updated = appUserRepository.save(toUpdate);
        return AppUserMapper.toAppUserReadModel(updated);
    }

    public AppUserReadModel update(AppUserWriteModel appUser) throws AppUserNotFoundException, EmailNotFoundException {
        AppUser toUpdate = appUserRepository
                .findById(appUser.getId())
                .orElseThrow(AppUserNotFoundException::new);

        if (validateStringArgument(appUser.getFirstName())) {
            toUpdate.setFirstName(appUser.getFirstName());
        }
        if (validateStringArgument(appUser.getLastName())) {
            toUpdate.setLastName(appUser.getLastName());
        }
        if (validateStringArgument(appUser.getEmail())) {
            toUpdate.setEmail(appUser.getEmail());
        }
        if (validateStringArgument(appUser.getPassword())) {
            toUpdate.setPassword(appUser.getPassword());
        }
        if (validateStringArgument(appUser.getRole())) {
            toUpdate.setRole(appUser.getRole());
        }
        toUpdate.setEnabled(appUser.isEnabled());
        toUpdate.setLocked(appUser.isLocked());

        AppUser updated = appUserRepository.save(toUpdate);
        return AppUserMapper.toAppUserReadModel(updated);
    }

    private boolean validateStringArgument(String argument) {
        return argument != null && !argument.isBlank();
    }

    public void enableAppUser(Long id) throws AppUserNotFoundException {
        appUserRepository.findById(id).orElseThrow(AppUserNotFoundException::new);

        appUserRepository.enableAppUser(id);
    }

    public AppUserReadModel create(AppUserWriteModel appUser) throws AppUserNotFoundException {
        if (appUser.getId() != null) {
            throw new IllegalArgumentException("Id could be present.");
        }
        if (appUserRepository.existsByEmail(appUser.getEmail())) {
            throw new IllegalArgumentException("User already exists.");
        }
        AppUser toCreate = AppUserMapper.toAppUser(appUser);
        AppUser created = appUserRepository.save(toCreate);
        return AppUserMapper.toAppUserReadModel(created);
    }

}
