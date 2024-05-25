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
        return "This is public access without any authentication. You should first signup at /api/auth/signup than login at /api/auth/signin.";
    }

    @PostMapping("/signup")
    public ResponseEntity<AuthReqRespDTO> signUp(@RequestBody AuthReqRespDTO signUpRequest){
        return  ResponseEntity.ok(loginAndRegisterFacade.signUp(signUpRequest));
    }

    @GetMapping(path = "/confirm")
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
    ResponseEntity<AuthReqRespDTO> deleteUser(@RequestBody AuthReqRespDTO deleteRequest) throws AppUserNotFoundException {
        return ResponseEntity.ok(loginAndRegisterFacade.deleteUser(deleteRequest));
    }

    @PutMapping("/user/updateUser")
    ResponseEntity<AuthReqRespDTO> updateUser(@RequestBody AuthReqRespDTO updateRequest){
        return ResponseEntity.ok(loginAndRegisterFacade.updateUser(updateRequest));
    }
}
