package pl.iseebugs.Security.domain.account.delete;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface DeleteTokenRepository extends JpaRepository<DeleteToken, Long> {

    Optional<DeleteToken> findByToken(String token);

    @Query("SELECT c FROM DeleteToken c WHERE c.appUserId = ?1")
    Optional<DeleteToken> findTokenByAppUserId(Long id);

    @Transactional
    @Modifying
    @Query("UPDATE DeleteToken c " +
            "SET c.confirmedAt = ?2 " +
            "WHERE c.token = ?1")
    void updateConfirmedAt(String token,
                          LocalDateTime confirmedAt);

    @Transactional
    @Modifying
    @Query("DELETE FROM DeleteToken c WHERE c.appUserId = ?1")
    void deleteByAppUserId(Long id);

}
