package pl.iseebugs.Security.infrastructure.security;

import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
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

    //TODO:
    //signUp
    //confirm
    //SingIn
    //refresh

}
