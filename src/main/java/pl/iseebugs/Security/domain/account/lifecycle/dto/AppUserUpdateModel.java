package pl.iseebugs.Security.domain.account.lifecycle.dto;

import lombok.Builder;

@Builder
public record AppUserUpdateModel(
        Long id,
        String firstName,
        String lastName,
        String email) {
}

