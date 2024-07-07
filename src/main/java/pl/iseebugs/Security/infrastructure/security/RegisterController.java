package pl.iseebugs.Security.infrastructure.security;

import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;
import pl.iseebugs.Security.infrastructure.email.InvalidEmailTypeException;
import pl.iseebugs.Security.infrastructure.security.projection.AuthReqRespDTO;

@AllArgsConstructor
@RestController
@RequestMapping("/api/auth")
class RegisterController {

    LoginAndRegisterFacade loginAndRegisterFacade;

    @GetMapping()
    public String goHome(){
        return "This is path with public access.";
    }

    @PostMapping("/signup")
    public ResponseEntity<AuthReqRespDTO> signUp(@RequestBody AuthReqRespDTO signUpRequest) throws EmailConflictException, InvalidEmailTypeException {
        return  ResponseEntity.ok(loginAndRegisterFacade.signUp(signUpRequest));
    }

    @GetMapping(path = "/confirm")
    public ResponseEntity<AuthReqRespDTO> confirm(@RequestParam("token") String token) throws RegistrationTokenConflictException, TokenNotFoundException {
        return ResponseEntity.ok(loginAndRegisterFacade.confirmToken(token));
    }

    @GetMapping(path = "/confirm/refresh-confirmation-token")
    public ResponseEntity<AuthReqRespDTO> refreshConfirmationToken(@RequestParam("email") String email) throws TokenNotFoundException, InvalidEmailTypeException, RegistrationTokenConflictException {
        return ResponseEntity.ok(loginAndRegisterFacade.refreshConfirmationToken(email));
    }

    @PostMapping("/signin")
    public ResponseEntity<AuthReqRespDTO> signIn(@RequestBody AuthReqRespDTO signInRequest) throws TokenNotFoundException {
        return  ResponseEntity.ok(loginAndRegisterFacade.signIn(signInRequest));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthReqRespDTO> refreshToken(@RequestHeader("Authorization") String authHeader) throws Exception {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }
        String refreshToken = authHeader.substring(7);
        return ResponseEntity.ok(loginAndRegisterFacade.refreshToken(refreshToken));
    }

    @DeleteMapping("/users")
    ResponseEntity<AuthReqRespDTO> deleteUser(@RequestHeader("Authorization") String authHeader) throws Exception {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }
        String accessToken = authHeader.substring(7);
        return ResponseEntity.ok(loginAndRegisterFacade.deleteUser(accessToken));
    }

    @PatchMapping("/users")
    ResponseEntity<AuthReqRespDTO> updateUser(@RequestHeader("Authorization") String authHeader,
                                              @RequestBody AuthReqRespDTO updateRequest) throws Exception {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }
        String refreshToken = authHeader.substring(7);
        return ResponseEntity.ok(loginAndRegisterFacade.updateUser(refreshToken, updateRequest));
    }

    @GetMapping(path = "/delete-confirm")
    public ResponseEntity<AuthReqRespDTO> deleteConfirm(@RequestParam("token") String token) throws RegistrationTokenConflictException, TokenNotFoundException {
        return ResponseEntity.ok(loginAndRegisterFacade.confirmDeleteToken(token));
    }
}
