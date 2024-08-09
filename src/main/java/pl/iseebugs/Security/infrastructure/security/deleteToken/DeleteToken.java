package pl.iseebugs.Security.infrastructure.security.deleteToken;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import pl.iseebugs.Security.domain.user.AppUser;

import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@Entity
public class DeleteToken {

    @SequenceGenerator(
            name = "delete_token_sequence",
            sequenceName = "delete_token_sequence",
            allocationSize = 1
    )
    @Id
    @GeneratedValue(
            strategy = GenerationType.SEQUENCE,
            generator = "delete_token_sequence"
    )
    private Long id;

    @Column(nullable = false)
    private String token;

    @Column(nullable = false)
    private LocalDateTime createdAt;
    @Column(nullable = false)
    private LocalDateTime expiresAt;
    private LocalDateTime confirmedAt;

    private Long appUserId;

    public DeleteToken(final String token,
                       final LocalDateTime createdAt,
                       final LocalDateTime expiresAt,
                       final Long appUserId) {
        this.token = token;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
        this.appUserId = appUserId;
    }
}
