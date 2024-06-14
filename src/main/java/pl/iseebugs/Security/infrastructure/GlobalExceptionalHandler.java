package pl.iseebugs.Security.infrastructure;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import pl.iseebugs.Security.infrastructure.security.EmailConflictException;
import pl.iseebugs.Security.infrastructure.security.projection.AuthReqRespDTO;

@ControllerAdvice
class GlobalExceptionalHandler {

    @ExceptionHandler(EmailConflictException.class)
    ResponseEntity<AuthReqRespDTO> handlerEmailConflictException(EmailConflictException e){
        AuthReqRespDTO response = new AuthReqRespDTO();
        response.setStatusCode(409);
        response.setError(e.getClass().getSimpleName());
        response.setMessage(e.getMessage());
        return ResponseEntity.ok().body(response);
    }
}
