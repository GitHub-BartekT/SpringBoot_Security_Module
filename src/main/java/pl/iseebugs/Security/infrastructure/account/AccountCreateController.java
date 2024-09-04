package pl.iseebugs.Security.infrastructure.account;

import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import pl.iseebugs.Security.domain.account.EmailNotFoundException;
import pl.iseebugs.Security.domain.account.create.AccountCreateFacade;
import pl.iseebugs.Security.domain.email.EmailSender;
import pl.iseebugs.Security.domain.email.InvalidEmailTypeException;
import pl.iseebugs.Security.domain.account.create.RegistrationTokenConflictException;
import pl.iseebugs.Security.domain.account.TokenNotFoundException;
import pl.iseebugs.Security.domain.security.projection.AuthReqRespDTO;
import pl.iseebugs.Security.domain.user.AppUserNotFoundException;

@AllArgsConstructor
@RestController
@RequestMapping("/api/auth/create")
class AccountCreateController {

    AccountCreateFacade accountCreateFacade;

    @PostMapping("/signup")
    public ResponseEntity<AuthReqRespDTO> signUp(@RequestBody AuthReqRespDTO signUpRequest) throws EmailSender.EmailConflictException, InvalidEmailTypeException, AppUserNotFoundException {
        return ResponseEntity.ok(accountCreateFacade.signUp(signUpRequest));
    }

    @GetMapping(path = "/confirm")
    public ResponseEntity<AuthReqRespDTO> confirm(@RequestParam("token") String token) throws RegistrationTokenConflictException, TokenNotFoundException, AppUserNotFoundException {
        return ResponseEntity.ok(accountCreateFacade.confirmToken(token));
    }

    @GetMapping(path = "/refresh-confirmation-token")
    public ResponseEntity<AuthReqRespDTO> refreshConfirmationToken(@RequestParam("email") String email) throws TokenNotFoundException, InvalidEmailTypeException, RegistrationTokenConflictException, AppUserNotFoundException, EmailNotFoundException {
        return ResponseEntity.ok(accountCreateFacade.refreshConfirmationToken(email));
    }
}

