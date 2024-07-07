package pl.iseebugs.Security.infrastructure.security.deleteToken;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.user.AppUser;
import pl.iseebugs.Security.infrastructure.security.TokenNotFoundException;
import pl.iseebugs.Security.infrastructure.security.token.ConfirmationToken;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@AllArgsConstructor
public class DeleteTokenService {

    private final DeleteTokenRepository deleteTokenRepository;

    public void saveDeleteToken(DeleteToken token){
        deleteTokenRepository.save(token);
    }

    public Optional<DeleteToken> getToken(String token) {
        return deleteTokenRepository.findByToken(token);
    }

    public Optional<DeleteToken> getTokenByEmail(String email) {
        return deleteTokenRepository.findTokenByEmail(email);
    }

    public void setConfirmedAt(String token) {
        deleteTokenRepository.updateConfirmedAt(
                token, LocalDateTime.now());
    }
}
