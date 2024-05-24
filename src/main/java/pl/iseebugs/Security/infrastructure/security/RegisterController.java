package pl.iseebugs.Security.infrastructure.security;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
class RegisterController {

    @GetMapping()
    public String goHome(){
        return "This is public access without any authentication. You should first signup at /api/auth/signup than login at /api/auth/signin.";
    }
}
