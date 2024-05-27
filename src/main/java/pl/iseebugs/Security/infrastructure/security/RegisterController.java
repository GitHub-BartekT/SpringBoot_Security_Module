package pl.iseebugs.Security.infrastructure.security;

import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import pl.iseebugs.Security.domain.user.AppUser;
import pl.iseebugs.Security.domain.user.AppUserNotFoundException;
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
    public ResponseEntity<AuthReqRespDTO> signUp(@RequestBody AuthReqRespDTO signUpRequest){
        return  ResponseEntity.ok(loginAndRegisterFacade.signUp(signUpRequest));
    }

    @PostMapping(path = "/confirm")
    public ResponseEntity<AuthReqRespDTO> confirm(@RequestParam("token") String token) {
        return ResponseEntity.ok(loginAndRegisterFacade.confirmToken(token));
    }

    @PostMapping("/signin")
    public ResponseEntity<AuthReqRespDTO> signIn(@RequestBody AuthReqRespDTO signInRequest){
        return  ResponseEntity.ok(loginAndRegisterFacade.signIn(signInRequest));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthReqRespDTO> refreshToken(@RequestHeader("Authorization") String authHeader){
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }
        String refreshToken = authHeader.substring(7);
        return ResponseEntity.ok(loginAndRegisterFacade.refreshToken(refreshToken));
    }

    @DeleteMapping("/user/deleteUser")
    ResponseEntity<AuthReqRespDTO> deleteUser(@RequestHeader("Authorization") String authHeader) throws AppUserNotFoundException {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }
        String refreshToken = authHeader.substring(7);
        return ResponseEntity.ok(loginAndRegisterFacade.deleteUser(refreshToken));
    }

    @PutMapping("/user/updateUser")
    ResponseEntity<AuthReqRespDTO> updateUser(@RequestHeader("Authorization") String authHeader,
                                              @RequestBody AuthReqRespDTO updateRequest){
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }
        String refreshToken = authHeader.substring(7);
        return ResponseEntity.ok(loginAndRegisterFacade.updateUser(refreshToken, updateRequest));
    }
}
