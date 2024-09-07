package pl.iseebugs.Security.domain.account.lifecycle.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

import java.util.Date;

@Getter
@AllArgsConstructor
@Builder
public class LoginReadModel {
    String accessToken;
    Date accessTokenExpiresAt;
    String refreshToken;
    Date refreshTokenExpiresAt;
    String email;
    String role;
    boolean created;
}
