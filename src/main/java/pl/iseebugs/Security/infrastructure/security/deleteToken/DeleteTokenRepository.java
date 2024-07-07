package pl.iseebugs.Security.infrastructure.security.deleteToken;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import pl.iseebugs.Security.infrastructure.security.token.ConfirmationToken;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface DeleteTokenRepository extends JpaRepository<DeleteToken, Long> {

    Optional<DeleteToken> findByToken(String token);

    @Query("SELECT c FROM DeleteToken c WHERE c.appUser.email = ?1")
    Optional<DeleteToken> findTokenByEmail(String email);

    @Transactional
    @Modifying
    @Query("UPDATE DeleteToken c " +
            "SET c.confirmedAt = ?2 " +
            "WHERE c.token = ?1")
    void updateConfirmedAt(String token,
                          LocalDateTime confirmedAt);

    @Transactional
    @Modifying
    @Query("DELETE FROM DeleteToken c WHERE c.appUser.id = ?1")
    void deleteByAppUserId(Long id);

}
