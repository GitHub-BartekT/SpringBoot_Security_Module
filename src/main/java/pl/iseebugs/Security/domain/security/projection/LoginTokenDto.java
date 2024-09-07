package pl.iseebugs.Security.domain.security.projection;

import lombok.Builder;

import java.util.Date;

@Builder
public record LoginTokenDto(String token, Date expiresAt) {
}
