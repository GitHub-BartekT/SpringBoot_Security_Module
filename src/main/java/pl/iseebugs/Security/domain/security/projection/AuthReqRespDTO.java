package pl.iseebugs.Security.domain.security.projection;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
public class AuthReqRespDTO {
    private int statusCode;
    private String error;
    private String message;
    private String token;
    private String refreshToken;
    private String expirationTime;
    private String email;
    private String firstName;
    private String role;
    private String password;
    private String lastName;
}