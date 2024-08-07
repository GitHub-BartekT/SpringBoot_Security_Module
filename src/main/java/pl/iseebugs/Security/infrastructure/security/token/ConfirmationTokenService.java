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

    public Optional<ConfirmationToken> getToken(String token) {
        return confirmationTokenRepository.findByToken(token);
    }

    public Optional<ConfirmationToken> getTokenByEmail(String email) {
        return confirmationTokenRepository.findTokenByEmail(email);
    }

    public int setConfirmedAt(String token) {
        return confirmationTokenRepository.updateConfirmedAt(
                token, LocalDateTime.now());
    }

    public void deleteConfirmationToken(AppUser appUser){
        confirmationTokenRepository.deleteByAppUserId(appUser.getId());
    }

    public boolean isConfirmed(String email) throws TokenNotFoundException {
        ConfirmationToken confirmationToken = confirmationTokenRepository.findTokenByEmail(email)
                .orElseThrow(() -> new TokenNotFoundException("Confirmation token not found"));
        return confirmationToken.getConfirmedAt().isBefore(LocalDateTime.now());
    }
}
