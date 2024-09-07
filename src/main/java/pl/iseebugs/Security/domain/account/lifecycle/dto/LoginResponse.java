package pl.iseebugs.Security.domain.account.lifecycle.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

import java.util.Date;

@Getter
@AllArgsConstructor
@Builder
public class LoginResponse {
    String accessToken;
    Date accessTokenExpiresAt;
    String refreshToken;
    Date refreshTokenExpiresAt;
}
