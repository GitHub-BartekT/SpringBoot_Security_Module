package pl.iseebugs.Security.infrastructure.security.token;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.user.AppUser;
import pl.iseebugs.Security.infrastructure.security.TokenNotFoundException;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@AllArgsConstructor
public class ConfirmationTokenService {

    private final ConfirmationTokenRepository confirmationTokenRepository;

    public void saveConfirmationToken(ConfirmationToken token){
        confirmationTokenRepository.save(token);
    }

    public Optional<ConfirmationToken> getTokenByToken(String token) {
        return confirmationTokenRepository.findByToken(token);
    }

    public Optional<ConfirmationToken> getTokenByUserId(Long id) {
        return confirmationTokenRepository.findTokenByEmail(id);
    }

    public int setConfirmedAt(String token) {
        return confirmationTokenRepository.updateConfirmedAt(
                token, LocalDateTime.now());
    }

    public void deleteConfirmationToken(AppUser appUser){
        confirmationTokenRepository.deleteByAppUserId(appUser.getId());
    }

    public boolean isConfirmed(Long id) throws TokenNotFoundException {
        ConfirmationToken confirmationToken = confirmationTokenRepository.findTokenByEmail(id)
                .orElseThrow(() -> new TokenNotFoundException("Confirmation token not found"));
        return confirmationToken.getConfirmedAt().isBefore(LocalDateTime.now());
    }
}
