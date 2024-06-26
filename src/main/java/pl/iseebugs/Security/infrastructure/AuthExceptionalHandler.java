package pl.iseebugs.Security.infrastructure;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import pl.iseebugs.Security.infrastructure.security.BadTokenTypeException;
import pl.iseebugs.Security.infrastructure.security.EmailConflictException;
import pl.iseebugs.Security.infrastructure.security.RegistrationTokenConflictException;
import pl.iseebugs.Security.infrastructure.security.TokenNotFoundException;
import pl.iseebugs.Security.infrastructure.security.projection.AuthReqRespDTO;

@ControllerAdvice
class AuthExceptionalHandler {

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

    @ExceptionHandler(BadCredentialsException.class)
    ResponseEntity<AuthReqRespDTO> handlerBadCredentialsException(BadCredentialsException e){
        AuthReqRespDTO response = new AuthReqRespDTO();
        response.setStatusCode(403);
        response.setError(e.getClass().getSimpleName());
        response.setMessage(e.getMessage());
        return ResponseEntity.ok().body(response);
    }
}
