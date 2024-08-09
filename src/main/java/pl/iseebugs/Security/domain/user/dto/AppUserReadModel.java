package pl.iseebugs.Security.domain.user.dto;

import lombok.Builder;
import lombok.Getter;

@Builder
public record AppUserReadModel(
        Long id,
        String firstName,
        String lastName,
        String email,
        String password,
        String role,
        Boolean locked,
        Boolean enabled) {
}
