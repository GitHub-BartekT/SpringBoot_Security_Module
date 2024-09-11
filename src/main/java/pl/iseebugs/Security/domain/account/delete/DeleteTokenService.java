package pl.iseebugs.Security.domain.account.delete;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.account.TokenNotFoundException;
import pl.iseebugs.Security.domain.account.create.ConfirmationToken;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
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

    public Optional<DeleteToken> getTokenByUserId(Long id) {
        return deleteTokenRepository.findTokenByAppUserId(id);
    }

    public void setConfirmedAt(String token) {
        deleteTokenRepository.updateConfirmedAt(
                token, LocalDateTime.now());
    }

    public Optional<DeleteToken> getTokenByToken(String token) {
        return deleteTokenRepository.findByToken(token);
    }

    public Date calculateTokenExpiration(String token) throws TokenNotFoundException {
        DeleteToken deleteToken = getTokenByToken(token)
                .orElseThrow(() -> new TokenNotFoundException("Token not found."));
        return Date.from(deleteToken.getExpiresAt().atZone(ZoneId.systemDefault()).toInstant());
    }
}
