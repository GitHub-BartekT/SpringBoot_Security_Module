package pl.iseebugs.Security.infrastructure;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import pl.iseebugs.Security.domain.ApiResponse;
import pl.iseebugs.Security.domain.account.ApiResponseFactory;
import pl.iseebugs.Security.domain.account.BadTokenTypeException;
import pl.iseebugs.Security.domain.account.EmailNotFoundException;
import pl.iseebugs.Security.domain.account.TokenNotFoundException;
import pl.iseebugs.Security.domain.account.create.RegistrationTokenConflictException;
import pl.iseebugs.Security.domain.user.AppUserNotFoundException;

@ControllerAdvice
class AuthExceptionalHandler {

    @ExceptionHandler(UsernameNotFoundException.class)
    ResponseEntity<ApiResponse<Void>> handlerUsernameNotFoundException(UsernameNotFoundException e){
        return ResponseEntity.ok().body(
                ApiResponseFactory.createResponseWithoutData(
                        HttpStatus.NOT_FOUND.value(),
                        e.getMessage()));
    }

    @ExceptionHandler(BadTokenTypeException.class)
    ResponseEntity<ApiResponse<Void>> handlerBadTokenTypeException(BadTokenTypeException e){
        return ResponseEntity.ok().body(
                ApiResponseFactory.createResponseWithoutData(
                        HttpStatus.UNAUTHORIZED.value(),
                        e.getMessage()));
    }

    @ExceptionHandler(CredentialsExpiredException.class)
    ResponseEntity<ApiResponse<Void>> handlerCredentialsExpiredException(CredentialsExpiredException e){
        return ResponseEntity.ok().body(
                ApiResponseFactory.createResponseWithoutData(
                        HttpStatus.FORBIDDEN.value(),
                        e.getMessage()));
    }

    @ExceptionHandler(TokenNotFoundException.class)
    ResponseEntity<ApiResponse<Void>>  handlerTokenNotFoundException(TokenNotFoundException e){
        return ResponseEntity.ok().body(
                ApiResponseFactory.createResponseWithoutData(
                        HttpStatus.UNAUTHORIZED.value(),
                        e.getMessage()));
    }

    @ExceptionHandler(RegistrationTokenConflictException.class)
    ResponseEntity<ApiResponse<Void>> handlerRegistrationTokenConflictException(RegistrationTokenConflictException e){
        return ResponseEntity.ok().body(
                ApiResponseFactory.createResponseWithoutData(
                        HttpStatus.CONFLICT.value(),
                        e.getMessage()));
    }

    @ExceptionHandler(BadCredentialsException.class)
    ResponseEntity<ApiResponse<Void>> handlerBadCredentialsException(BadCredentialsException e){
        return ResponseEntity.ok().body(
                ApiResponseFactory.createResponseWithoutData(
                        HttpStatus.FORBIDDEN.value(),
                        e.getMessage()));
    }


}
