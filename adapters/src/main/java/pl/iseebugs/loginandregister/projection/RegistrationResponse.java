package pl.iseebugs.loginandregister.projection;

import lombok.Data;

public record RegistrationResponse (String token, String message, boolean isRegistered){
}
