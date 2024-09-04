package pl.iseebugs.Security.domain.user;

import jakarta.validation.constraints.NotNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
@Transactional
public interface AppUserRepository extends JpaRepository<AppUser,Long> {
    @Query("SELECT a FROM AppUser a WHERE a.email = ?1")
    Optional<AppUser> findByEmail(String email);

    @Query("SELECT a FROM AppUser a WHERE a.id = ?1")
    @NotNull Optional<AppUser> findById(@NotNull Long id);

    @Query("SELECT COUNT(a) > 0 FROM AppUser a WHERE a.email = ?1")
    boolean existsByEmail(String email);

    @Transactional
    @Modifying
    @Query("UPDATE AppUser a " +
            "SET a.enabled = TRUE WHERE a.id = ?1")
    void enableAppUser(Long id);

    AppUser save(AppUser entity);

    @Transactional
    @Modifying
    @Query("DELETE FROM AppUser a WHERE a.email = ?1")
    void deleteByEmail(String email);

}
