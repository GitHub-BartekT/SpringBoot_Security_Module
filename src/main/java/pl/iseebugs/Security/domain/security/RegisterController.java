package pl.iseebugs.Security.domain.security;

import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import pl.iseebugs.Security.domain.account.EmailNotFoundException;
import pl.iseebugs.Security.domain.account.TokenNotFoundException;
import pl.iseebugs.Security.domain.account.lifecycle.LifecycleAccountFacade;
import pl.iseebugs.Security.domain.user.AppUserNotFoundException;
import pl.iseebugs.Security.domain.security.projection.AuthReqRespDTO;
import pl.iseebugs.Security.domain.user.dto.AppUserWriteModel;

@Log4j2
@AllArgsConstructor
@RestController
@RequestMapping("/api/auth")
public class RegisterController {

    SecurityFacade securityFacade;
    LifecycleAccountFacade lifecycleAccountFacade;

    @PostMapping("/signin")
    public ResponseEntity<AuthReqRespDTO> signIn(@RequestBody AuthReqRespDTO signInRequest) throws TokenNotFoundException, AppUserNotFoundException, EmailNotFoundException {
        return  ResponseEntity.ok(lifecycleAccountFacade.signIn(signInRequest));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthReqRespDTO> refreshToken(@RequestHeader("Authorization") String authHeader) throws Exception {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }
        String refreshToken = authHeader.substring(7);
        return ResponseEntity.ok(securityFacade.refreshToken(refreshToken));
    }

    @PatchMapping("/users")
    ResponseEntity<AuthReqRespDTO> updateUser(@RequestHeader("Authorization") String authHeader,
                                              @RequestBody AppUserWriteModel appUserWriteModel) throws Exception {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }
        String accessToken = authHeader.substring(7);
        return ResponseEntity.ok(securityFacade.updateUser(accessToken, appUserWriteModel));
    }

    @PatchMapping("/users/forgotten-password")
    ResponseEntity<AuthReqRespDTO> generateNewPassword(@RequestHeader("Authorization") String authHeader) throws Exception {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }
        String accessToken = authHeader.substring(7);
        return ResponseEntity.ok(securityFacade.resetPasswordAndNotify(accessToken));
    }

    @PatchMapping("/users/password")
    ResponseEntity<AuthReqRespDTO> generateNewPassword(@RequestHeader("Authorization") String authHeader, @RequestBody AuthReqRespDTO reqRespDTO) throws Exception {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }
        String accessToken = authHeader.substring(7);
        return ResponseEntity.ok(securityFacade.updatePassword(accessToken, reqRespDTO));
    }
}
