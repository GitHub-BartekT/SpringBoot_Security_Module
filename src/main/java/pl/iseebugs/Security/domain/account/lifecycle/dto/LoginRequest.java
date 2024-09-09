package pl.iseebugs.Security.domain.account.lifecycle.dto;

import lombok.*;

@Getter
@AllArgsConstructor
@Builder
public class LoginRequest {
    private String email;
    private String password;
}