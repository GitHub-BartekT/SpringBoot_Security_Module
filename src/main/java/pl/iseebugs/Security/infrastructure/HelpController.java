package pl.iseebugs.Security.infrastructure;

import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@AllArgsConstructor
@RestController
@RequestMapping("/api/auth")
class HelpController {

    @GetMapping
    public String publicAccessEndpoint(){
        return "This is path with public access.";
    }
}
