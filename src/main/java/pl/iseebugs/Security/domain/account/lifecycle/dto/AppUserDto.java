package pl.iseebugs.Security.domain.account.lifecycle.dto;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class AppUserDto {
    private Long id;
    private String firstName;
    private String lastName;
    private String email;
    private String message;
}

