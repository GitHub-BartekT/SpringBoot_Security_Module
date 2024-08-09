package pl.iseebugs.Security.domain.user;

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
    Optional<AppUser> findById(Long id);

    @Transactional
    @Modifying
    @Query("UPDATE AppUser a " +
            "SET a.enabled = TRUE WHERE a.email = ?1")
    void enableAppUser(String email);

    @Transactional
    @Modifying
    @Query("DELETE FROM AppUser a WHERE a.email = ?1")
    void deleteByEmail(String email);

}
