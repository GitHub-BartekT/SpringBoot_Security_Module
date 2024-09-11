package pl.iseebugs.Security.domain.account.create;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import pl.iseebugs.Security.domain.account.AccountHelper;
import pl.iseebugs.Security.domain.user.AppUser;
import pl.iseebugs.Security.domain.account.TokenNotFoundException;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Optional;

import static pl.iseebugs.Security.domain.account.AccountHelper.CONFIRMATION_ACCOUNT_TOKEN_EXPIRATION_TIME;
import static pl.iseebugs.Security.domain.account.AccountHelper.getUUID;

@Service
@AllArgsConstructor
class ConfirmationTokenService {

    private final ConfirmationTokenRepository confirmationTokenRepository;
    private final AccountHelper accountHelper;

    public String createNewConfirmationToken(Long userId) {
        String token = getUUID();
        ConfirmationToken confirmationToken = new ConfirmationToken(
                token,
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(CONFIRMATION_ACCOUNT_TOKEN_EXPIRATION_TIME),
                userId
        );
        saveConfirmationToken(confirmationToken);
        return token;
    }

    public Date calculateTokenExpiration(String token) throws TokenNotFoundException {
        ConfirmationToken confirmationToken = getTokenByToken(token)
                .orElseThrow(() -> new TokenNotFoundException("Token not found."));
        return Date.from(confirmationToken.getExpiresAt().atZone(ZoneId.systemDefault()).toInstant());
    }

    public void saveConfirmationToken(ConfirmationToken token){
        confirmationTokenRepository.save(token);
    }

    public Optional<ConfirmationToken> getTokenByToken(String token) {
        return confirmationTokenRepository.findByToken(token);
    }

    public Optional<ConfirmationToken> getTokenByUserId(Long id) {
        return confirmationTokenRepository.findTokenByEmail(id);
    }

    public void setConfirmedAt(String token) {
        confirmationTokenRepository.updateConfirmedAt(
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
