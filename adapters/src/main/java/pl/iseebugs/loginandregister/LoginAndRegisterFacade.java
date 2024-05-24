package pl.iseebugs.loginandregister;

import org.springframework.http.ResponseEntity;
import pl.iseebugs.loginandregister.projection.AuthReqRespDTO;
import pl.iseebugs.loginandregister.projection.RegistrationRequest;

class LoginAndRegisterFacade {

    //TODO: logic
    // signUp(signUpRequest)
    // confirmRegisterToken(registerToken)
    // signIn(signInRequest)
    // refreshToken(refreshTokenRequest)

    AuthReqRespDTO signUp(final RegistrationRequest signUpRequest) {
        return null;
    }

    ResponseEntity<AuthReqRespDTO> confirmRegistrationToken(final String token) {
        return null;
    }

    AuthReqRespDTO signIn(final AuthReqRespDTO signInRequest) {
        return null;
    }

    AuthReqRespDTO refreshToken(final AuthReqRespDTO refreshTokenRequest) {
        return null;
    }
}
