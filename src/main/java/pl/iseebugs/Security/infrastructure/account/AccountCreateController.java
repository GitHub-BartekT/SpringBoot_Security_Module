package pl.iseebugs.Security.infrastructure.account;

import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import pl.iseebugs.Security.domain.ApiResponse;
import pl.iseebugs.Security.domain.account.EmailNotFoundException;
import pl.iseebugs.Security.domain.account.TokenNotFoundException;
import pl.iseebugs.Security.domain.account.create.AccountCreateFacade;
import pl.iseebugs.Security.domain.account.create.RegistrationTokenConflictException;
import pl.iseebugs.Security.domain.account.lifecycle.dto.LoginRequest;
import pl.iseebugs.Security.domain.email.EmailSender;
import pl.iseebugs.Security.domain.email.InvalidEmailTypeException;
import pl.iseebugs.Security.domain.security.projection.LoginTokenDto;
import pl.iseebugs.Security.domain.user.AppUserNotFoundException;

@AllArgsConstructor
@RestController
@RequestMapping("/api/auth/create")
class AccountCreateController {

    AccountCreateFacade accountCreateFacade;

    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<LoginTokenDto>> signUp(@RequestBody LoginRequest signUpRequest) throws EmailSender.EmailConflictException, InvalidEmailTypeException, AppUserNotFoundException, TokenNotFoundException {
        return ResponseEntity.ok(accountCreateFacade.signUp(signUpRequest));
    }

    @GetMapping(path = "/confirm")
    public ResponseEntity<ApiResponse> confirm(@RequestParam("token") String token) throws RegistrationTokenConflictException, TokenNotFoundException, AppUserNotFoundException {
        return ResponseEntity.ok(accountCreateFacade.confirmToken(token));
    }

    @GetMapping(path = "/refresh-confirmation-token")
    public ResponseEntity<ApiResponse<LoginTokenDto>> refreshConfirmationToken(@RequestParam("email") String email) throws TokenNotFoundException, InvalidEmailTypeException, RegistrationTokenConflictException, AppUserNotFoundException, EmailNotFoundException {
        return ResponseEntity.ok(accountCreateFacade.refreshConfirmationToken(email));
    }
}


