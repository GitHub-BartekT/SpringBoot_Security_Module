package pl.iseebugs.loginandregister;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import pl.iseebugs.loginandregister.projection.AuthReqRespDTO;
import pl.iseebugs.loginandregister.projection.RegistrationRequest;
import pl.iseebugs.loginandregister.projection.RegistrationResponse;

@RestController
@RequestMapping("/api/auth")
class RegisterController {

    LoginAndRegisterFacade loginAndRegisterFacade;

    @PostMapping("/signup")
    public ResponseEntity<AuthReqRespDTO> signUp(@RequestBody RegistrationRequest signUpRequest){
        return  ResponseEntity.ok(loginAndRegisterFacade.signUp(signUpRequest));
    }

    @GetMapping(path = "/confirm")
    public ResponseEntity<AuthReqRespDTO> confirm(@RequestParam("token") String token) {
        return loginAndRegisterFacade.confirmRegistrationToken(token);
    }


    @PostMapping("/signin")
    public ResponseEntity<AuthReqRespDTO> signIn(@RequestBody AuthReqRespDTO signInRequest){
        return  ResponseEntity.ok(loginAndRegisterFacade.signIn(signInRequest));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthReqRespDTO> refreshToken(@RequestBody AuthReqRespDTO refreshTokenRequest){
        return  ResponseEntity.ok(loginAndRegisterFacade.refreshToken(refreshTokenRequest));
    }
}
