package pl.iseebugs.Security.infrastructure.security.deleteToken;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

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

    public Optional<DeleteToken> getTokenByUserId(Long id) {
        return deleteTokenRepository.findTokenByAppUserId(id);
    }

    public void setConfirmedAt(String token) {
        deleteTokenRepository.updateConfirmedAt(
                token, LocalDateTime.now());
    }
}
