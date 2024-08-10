package pl.iseebugs.Security.domain.security;

import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import pl.iseebugs.Security.domain.email.EmailSender;
import pl.iseebugs.Security.domain.email.InvalidEmailTypeException;
import pl.iseebugs.Security.domain.loginandregister.RegistrationTokenConflictException;
import pl.iseebugs.Security.domain.user.AppUserNotFoundException;
import pl.iseebugs.Security.domain.security.projection.AuthReqRespDTO;

@AllArgsConstructor
@RestController
@RequestMapping("/api/auth")
public class RegisterController {

    SecurityFacade securityFacade;

    @PostMapping("/signin")
    public ResponseEntity<AuthReqRespDTO> signIn(@RequestBody AuthReqRespDTO signInRequest) throws TokenNotFoundException, AppUserNotFoundException {
        return  ResponseEntity.ok(securityFacade.signIn(signInRequest));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthReqRespDTO> refreshToken(@RequestHeader("Authorization") String authHeader) throws Exception {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }
        String refreshToken = authHeader.substring(7);
        return ResponseEntity.ok(securityFacade.refreshToken(refreshToken));
    }

    @DeleteMapping("/users")
    ResponseEntity<AuthReqRespDTO> deleteUser(@RequestHeader("Authorization") String authHeader) throws Exception {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }
        String accessToken = authHeader.substring(7);
        return ResponseEntity.ok(securityFacade.deleteUser(accessToken));
    }

    @PatchMapping("/users")
    ResponseEntity<AuthReqRespDTO> updateUser(@RequestHeader("Authorization") String authHeader,
                                              @RequestBody AuthReqRespDTO updateRequest) throws Exception {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }
        String refreshToken = authHeader.substring(7);
        return ResponseEntity.ok(securityFacade.updateUser(refreshToken, updateRequest));
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

    @GetMapping("/delete-confirm")
    public ResponseEntity<AuthReqRespDTO> deleteConfirm(@RequestParam("token") String token) throws TokenNotFoundException, AppUserNotFoundException {
        return ResponseEntity.ok(securityFacade.confirmDeleteToken(token));
    }
}
