package pl.iseebugs.Security.infrastructure;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import pl.iseebugs.Security.domain.ApiResponse;
import pl.iseebugs.Security.domain.account.ApiResponseFactory;
import pl.iseebugs.Security.domain.account.EmailNotFoundException;
import pl.iseebugs.Security.domain.email.EmailSender;
import pl.iseebugs.Security.domain.email.InvalidEmailTypeException;
import pl.iseebugs.Security.domain.user.AppUserNotFoundException;

@ControllerAdvice
class GlobalExceptionalHandler {

    @ExceptionHandler(EmailSender.EmailConflictException.class)
    ResponseEntity<ApiResponse<Void>> handlerEmailConflictException(EmailSender.EmailConflictException e){
        return ResponseEntity.ok().body(
                ApiResponseFactory.createResponseWithoutData(
                        HttpStatus.CONFLICT.value(),
                        e.getMessage()));
    }

    @ExceptionHandler(InvalidEmailTypeException.class)
    ResponseEntity<ApiResponse<Void>> handlerInvalidEmailTypeException(InvalidEmailTypeException e){
        return ResponseEntity.ok().body(
                ApiResponseFactory.createResponseWithoutData(
                        HttpStatus.INTERNAL_SERVER_ERROR.value(),
                        e.getMessage()));
    }

    @ExceptionHandler(AppUserNotFoundException.class)
    ResponseEntity<ApiResponse<Void>> handlerAppUserNotFoundException(AppUserNotFoundException e){
        return ResponseEntity.ok().body(
                ApiResponseFactory.createResponseWithoutData(
                        HttpStatus.NOT_FOUND.value(),
                        e.getMessage()));
    }

    @ExceptionHandler(EmailNotFoundException.class)
    ResponseEntity<ApiResponse<Void>> handlerEmailNotFoundException(EmailNotFoundException e){
        return ResponseEntity.ok().body(
                ApiResponseFactory.createResponseWithoutData(
                        HttpStatus.NOT_FOUND.value(),
                        e.getMessage()));
    }
}
