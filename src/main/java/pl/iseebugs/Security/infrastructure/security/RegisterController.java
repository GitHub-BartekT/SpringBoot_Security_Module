package pl.iseebugs.Security.infrastructure.security;

import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;
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
    public ResponseEntity<AuthReqRespDTO> signUp(@RequestBody AuthReqRespDTO signUpRequest) throws EmailConflictException {
        return  ResponseEntity.ok(loginAndRegisterFacade.signUp(signUpRequest));
    }

    @GetMapping(path = "/confirm")
    public ResponseEntity<AuthReqRespDTO> confirm(@RequestParam("token") String token) throws RegistrationTokenConflictException, TokenNotFoundException {
        return ResponseEntity.ok(loginAndRegisterFacade.confirmToken(token));
    }

    @PostMapping("/signin")
    public ResponseEntity<AuthReqRespDTO> signIn(@RequestBody AuthReqRespDTO signInRequest){
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

    @DeleteMapping("/user/deleteUser")
    ResponseEntity<AuthReqRespDTO> deleteUser(@RequestHeader("Authorization") String authHeader) throws Exception {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }
        String accessToken = authHeader.substring(7);
        return ResponseEntity.ok(loginAndRegisterFacade.deleteUser(accessToken));
    }

    @PutMapping("/user/updateUser")
    ResponseEntity<AuthReqRespDTO> updateUser(@RequestHeader("Authorization") String authHeader,
                                              @RequestBody AuthReqRespDTO updateRequest) throws Exception {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }
        String refreshToken = authHeader.substring(7);
        return ResponseEntity.ok(loginAndRegisterFacade.updateUser(refreshToken, updateRequest));
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    ResponseEntity<AuthReqRespDTO> handlerUsernameNotFoundException(UsernameNotFoundException e){
        AuthReqRespDTO response = new AuthReqRespDTO();
        response.setStatusCode(404);
        response.setError(e.getClass().getSimpleName());
        response.setMessage(e.getMessage());
        return ResponseEntity.ok().body(response);
    }


    @ExceptionHandler(BadTokenTypeException.class)
    ResponseEntity<AuthReqRespDTO> handlerBadTokenTypeException(BadTokenTypeException e){
        AuthReqRespDTO response = new AuthReqRespDTO();
        response.setStatusCode(401);
        response.setError(e.getClass().getSimpleName());
        response.setMessage(e.getMessage());
        return ResponseEntity.ok().body(response);
    }

    @ExceptionHandler(CredentialsExpiredException.class)
    ResponseEntity<AuthReqRespDTO> handlerCredentialsExpiredException(CredentialsExpiredException e){
        AuthReqRespDTO response = new AuthReqRespDTO();
        response.setStatusCode(403);
        response.setError(e.getClass().getSimpleName());
        response.setMessage(e.getMessage());
        return ResponseEntity.ok().body(response);
    }

    @ExceptionHandler(TokenNotFoundException.class)
    ResponseEntity<AuthReqRespDTO> handlerTokenNotFoundException(TokenNotFoundException e){
        AuthReqRespDTO response = new AuthReqRespDTO();
        response.setStatusCode(401);
        response.setError(e.getClass().getSimpleName());
        response.setMessage(e.getMessage());
        return ResponseEntity.ok().body(response);
    }

    @ExceptionHandler(RegistrationTokenConflictException.class)
    ResponseEntity<AuthReqRespDTO> handlerRegistrationTokenConflictException(RegistrationTokenConflictException e){
        AuthReqRespDTO response = new AuthReqRespDTO();
        response.setStatusCode(409);
        response.setError(e.getClass().getSimpleName());
        response.setMessage(e.getMessage());
        return ResponseEntity.ok().body(response);
    }

    @ExceptionHandler(EmailConflictException.class)
    ResponseEntity<AuthReqRespDTO> handlerEmailConflictException(EmailConflictException e){
        AuthReqRespDTO response = new AuthReqRespDTO();
        response.setStatusCode(409);
        response.setError(e.getClass().getSimpleName());
        response.setMessage(e.getMessage());
        return ResponseEntity.ok().body(response);
    }

    @ExceptionHandler(BadCredentialsException.class)
    ResponseEntity<AuthReqRespDTO> handlerBadCredentialsException(BadCredentialsException e){
        AuthReqRespDTO response = new AuthReqRespDTO();
        response.setStatusCode(403);
        response.setError(e.getClass().getSimpleName());
        response.setMessage(e.getMessage());
        return ResponseEntity.ok().body(response);
    }
}
