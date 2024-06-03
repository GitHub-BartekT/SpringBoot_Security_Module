package pl.iseebugs.Security.infrastructure.security;

import lombok.extern.java.Log;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.util.StringUtils;
import pl.iseebugs.Security.BaseIntegrationTest;
import pl.iseebugs.Security.infrastructure.security.projection.AuthReqRespDTO;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Log
class UserRegistersAndDeletesAccountIntegrationTest extends BaseIntegrationTest {

    @Test
    void should_user_registers_changes_data_and_deletes_account() throws Exception {
    //Step 1: User tried to get JWT by requesting POST /auth/signin
    //with username='someTestUser', password='somePassword' and system returned UNAUTHORIZED
        // given && when
        log.info("Step 1.");
        ResultActions failedLoginRequest = mockMvc.perform(post("/api/auth/signin")
                .content("""
                        {
                        "firstName": "firstTestName",
                        "lastName": "lastTestName",
                        "email": "some@mail.com",
                        "password": "somePassword"
                        }
                        """.trim())
                .contentType(MediaType.APPLICATION_JSON_VALUE)
        );

        // then
        MvcResult registerActionResultFailed = failedLoginRequest.andExpect(status().isOk()).andReturn();
        String registerActionResultFailedJson = registerActionResultFailed.getResponse().getContentAsString();
        AuthReqRespDTO confirmResultFailedDto = objectMapper.readValue(registerActionResultFailedJson, AuthReqRespDTO.class);
        assertAll(
                () -> assertThat(confirmResultFailedDto.getStatusCode()).isEqualTo(404),
                () -> assertThat(confirmResultFailedDto.getError()).isEqualTo("User not found")
        );


    //Step 2: User made GET /{some public endpoint} and system returned OK(200) and some public response
        // given && when
        log.info("Step 2.");
        ResultActions publicAccess = mockMvc.perform(get("/api/auth")
                .contentType(MediaType.APPLICATION_JSON)
        );

        //then
        publicAccess.andExpect(status().isOk())
                .andExpect(content().string("This is path with public access.".trim()));


    //Step 3: user made POST /api/auth/signup with username="someTestUser", password="someTestPassword"
    //and system registered user with status OK(200) and register token="someToken"
        // given && when
        log.info("Step 3.");
        ResultActions successRegisterRequest = mockMvc.perform(post("/api/auth/signup")
                .content("""
                        {
                        "firstName": "firstTestName",
                        "lastName": "lastTestName",
                        "email": "some@mail.com",
                        "password": "somePassword"
                        }
                        """.trim())
                .contentType(MediaType.APPLICATION_JSON_VALUE)
        );

        // then
        MvcResult registerActionResult = successRegisterRequest.andExpect(status().isOk()).andReturn();
        String registerActionResultJson = registerActionResult.getResponse().getContentAsString();
        AuthReqRespDTO registerResultDto = objectMapper.readValue(registerActionResultJson, AuthReqRespDTO.class);

        String registrationToken = registerResultDto.getToken();

        final AuthReqRespDTO finalConfirmResultDto = registerResultDto;
        assertAll(
                () -> assertThat(finalConfirmResultDto.getStatusCode()).isEqualTo(201),
                () -> assertThat(finalConfirmResultDto.getMessage()).isEqualTo("User created successfully."),
                () -> assertThat(finalConfirmResultDto.getToken()).isNotBlank()
        );



    // Step 4: user made POST /api/auth/confirm with token="invalidToken" and system responses with status FORBIDDEN(403)
        // given && when
        log.info("Step 4.");
        String badToken = "not.valid.token";
        ResultActions badConfirmTokenRegisterRequest = mockMvc.perform(get("/api/auth/confirm?token=" + badToken)
                .contentType(MediaType.APPLICATION_JSON_VALUE)
        );

        // then
        MvcResult badConfirmTokenActionResult = badConfirmTokenRegisterRequest.andExpect(status().isOk()).andReturn();
        String badConfirmTokenActionResultJson = badConfirmTokenActionResult.getResponse().getContentAsString();
        AuthReqRespDTO badConfirmTokenResultDto = objectMapper.readValue(badConfirmTokenActionResultJson, AuthReqRespDTO.class);
        assertAll(
                () -> assertThat(badConfirmTokenResultDto.getStatusCode()).isEqualTo(401),
                () -> assertThat(badConfirmTokenResultDto.getError()).isEqualTo("BadCredentialsException"),
                () -> assertThat(badConfirmTokenResultDto.getMessage()).isEqualTo("Token not found.")
        );


    //Step 5: user made POST /api/auth/confirm with token="someToken" and system responses with status OK(200)
        // given && when
        log.info("Step 5.");
        ResultActions confirmRegisterRequest = mockMvc.perform(get("/api/auth/confirm?token=" + registrationToken)
                .contentType(MediaType.APPLICATION_JSON_VALUE)
        );

        // then
        MvcResult confirmActionResult = confirmRegisterRequest.andExpect(status().isOk()).andReturn();
        String confirmActionResultJson = confirmActionResult.getResponse().getContentAsString();
        AuthReqRespDTO confirmResultDto = objectMapper.readValue(confirmActionResultJson, AuthReqRespDTO.class);

        assertAll(
                () -> assertThat(confirmResultDto.getStatusCode()).isEqualTo(200),
                () -> assertThat(confirmResultDto.getMessage()).isEqualTo("User confirmed.")
        );


    //Step 6: user tried to get JWT by requesting POST /api/auth/signin with username="someTestUser", password="someTestPassword"
    //and system returned OK(200) and accessToken=AAAA.BBBB.CCC and refreshToken=DDDD.EEEE.FFF
        // given && when
        log.info("Step 6.");
        ResultActions loginRequest = mockMvc.perform(post("/api/auth/signin")
                .content("""
                        {
                        "firstName": "firstTestName",
                        "lastName": "lastTestName",
                        "email": "some@mail.com",
                        "password": "somePassword"
                        }
                        """.trim())
                .contentType(MediaType.APPLICATION_JSON_VALUE)
        );


        // then
        MvcResult loginActionResult = loginRequest.andExpect(status().isOk()).andReturn();
        String loginActionResultJson = loginActionResult.getResponse().getContentAsString();
        AuthReqRespDTO loginResultDto = objectMapper.readValue(loginActionResultJson, AuthReqRespDTO.class);

        String accessToken = loginResultDto.getToken();
        String refreshToken = loginResultDto.getRefreshToken();

        //then
        assertAll(
                () -> assertThat(loginResultDto.getStatusCode()).isEqualTo(200),
                () -> assertThat(loginResultDto.getMessage()).isEqualTo("Successfully singed in"),
                () -> assertThat(loginResultDto.getToken()).isNotBlank(),
                () -> assertThat(loginResultDto.getRefreshToken()).isNotBlank(),
                () -> assertThat(StringUtils.countOccurrencesOf(accessToken, ".")).isEqualTo(2),
                () -> assertThat(StringUtils.countOccurrencesOf(refreshToken, ".")).isEqualTo(2)
        );
    //Step 7: User made POST /api/auth/refresh with “Authorization: AAAA.BBBB.CCC” (access token)
    // and system returned UNAUTHORIZED(401)
        // given && when
        log.info("Step 7.");
        ResultActions badRefreshRegisterRequest = mockMvc.perform(post("/api/auth/refresh")
                .header("Authorization", "Bearer " + accessToken)
                .contentType(MediaType.APPLICATION_JSON_VALUE)
        );

        // then
        MvcResult badRefreshActionResult = badRefreshRegisterRequest.andExpect(status().isOk()).andReturn();
        String badRefreshActionResultJson = badRefreshActionResult.getResponse().getContentAsString();
        AuthReqRespDTO badRefreshResultDto = objectMapper.readValue(badRefreshActionResultJson, AuthReqRespDTO.class);


        //then
        assertAll(
                () -> assertThat(badRefreshResultDto.getStatusCode()).isEqualTo(401),
                () -> assertThat(badRefreshResultDto.getMessage()).isEqualTo("Invalid Token")
        );


    //Step 8: User made POST /api/auth/refresh with “Authorization: DDDD.EEEE.FFF (refresh token)
    // and system returned OK(200) and token=GGGG.HHHH.III and refreshToken=DDDD.EEEE.FFF
        // given && when
        log.info("Step 8.");
        ResultActions refreshRegisterRequest = mockMvc.perform(post("/api/auth/refresh")
             .header("Authorization", "Bearer " + refreshToken)
             .contentType(MediaType.APPLICATION_JSON_VALUE)
        );

        // then
        MvcResult refreshActionResult = refreshRegisterRequest.andExpect(status().isOk()).andReturn();
        String refreshActionResultJson = refreshActionResult.getResponse().getContentAsString();
        AuthReqRespDTO refreshResultDto = objectMapper.readValue(refreshActionResultJson, AuthReqRespDTO.class);

        String newAccessToken = refreshResultDto.getToken();
        String newRefreshToken = refreshResultDto.getRefreshToken();

        //then
        assertAll(
                () -> assertThat(refreshResultDto.getStatusCode()).isEqualTo(200),
                () -> assertThat(refreshResultDto.getMessage()).isEqualTo("Successfully Refreshed Token"),
                () -> assertThat(refreshResultDto.getToken()).isNotBlank(),
                () -> assertThat(refreshResultDto.getRefreshToken()).isNotBlank(),
                () -> assertThat(newRefreshToken.equals(refreshToken)),
                () -> assertThat(StringUtils.countOccurrencesOf(newAccessToken, ".")).isEqualTo(2),
                () -> assertThat(StringUtils.countOccurrencesOf(newRefreshToken, ".")).isEqualTo(2)
        );


    //Step 9: User made POST /api/auth/updateUser with header “Authorization: GGGG.HHHH.III” and new data
    // and system returned OK(200)
        // given && when
        log.info("Step 9.");
        ResultActions updateRegisterRequest = mockMvc.perform(put("/api/auth/user/updateUser")
                .header("Authorization", "Bearer " + newAccessToken)
                .content("""
                        {
                        "firstName": "Foo",
                        "lastName": "Bar",
                        "email": "some@mail.com",
                        "password": "newPassword"
                        }
                        """.trim())
                .contentType(MediaType.APPLICATION_JSON_VALUE)
        );

        // then
        MvcResult updateActionResult = updateRegisterRequest.andExpect(status().isOk()).andReturn();
        String updateActionResultJson = updateActionResult.getResponse().getContentAsString();
        AuthReqRespDTO updateResultDto = objectMapper.readValue(updateActionResultJson, AuthReqRespDTO.class);

        assertAll(
                () -> assertThat(updateResultDto.getStatusCode()).isEqualTo(200),
                () -> assertThat(updateResultDto.getMessage()).isEqualTo("User update successfully")
       );
    //Step 10:    User made DELETE /api/auth/deleteUser “Authorization: AAAA.BBBB.CCC” (refresh token)
    // and system returned UNAUTHORIZED(401)
        log.info("Step 10.");
        ResultActions badDeleteRegisterRequest = mockMvc.perform(delete("/api/auth/user/deleteUser")
                .header("Authorization", "Bearer " + refreshToken)
                .contentType(MediaType.APPLICATION_JSON_VALUE)
        );
        // then
        MvcResult badDelete = badDeleteRegisterRequest.andExpect(status().isForbidden()).andReturn();

        //then
        assertAll(
                () -> assertThat(badDelete.getResponse().getStatus()).isEqualTo(403)
        );


    //Step 11: User made DELETE /api/auth/deleteUser with “Authorization: AAAA.BBBB.CCC”
    //and system returned OK(204)
        log.info("Step 11.");
        ResultActions deleteRegisterRequest = mockMvc.perform(delete("/api/auth/user/deleteUser")
                .header("Authorization", "Bearer " + newAccessToken)
                .contentType(MediaType.APPLICATION_JSON_VALUE)
        );

        // then
        MvcResult delete = deleteRegisterRequest.andExpect(status().isOk()).andReturn();
        String deleteActionResultJson = delete.getResponse().getContentAsString();
        AuthReqRespDTO deleteResultDto = objectMapper.readValue(deleteActionResultJson, AuthReqRespDTO.class);

        //then
        assertAll(
                () -> assertThat(deleteResultDto.getStatusCode()).isEqualTo(204),
                () -> assertThat(deleteResultDto.getMessage()).isEqualTo("Successfully deleted user")
       );

    //Step 12: User tried to get JWT by requesting POST /auth/signin
    //with username='someTestUser', password='somePassword' and system returned UNAUTHORIZED
        // given && when
        log.info("Step 12.");
        ResultActions failedLoginRequestNoUser = mockMvc.perform(post("/api/auth/signin")
                .content("""
                        {
                        "firstName": "firstTestName",
                        "lastName": "lastTestName",
                        "email": "some@mail.com",
                        "password": "somePassword"
                        }
                        """.trim())
                .contentType(MediaType.APPLICATION_JSON_VALUE)
        );

        // then
        MvcResult registerActionResultFailedNoUser = failedLoginRequestNoUser.andExpect(status().isOk()).andReturn();
        String confirmActionResultFailedJsonNoUser = registerActionResultFailedNoUser.getResponse().getContentAsString();
        AuthReqRespDTO confirmResultFailedDtoNoUser = objectMapper.readValue(confirmActionResultFailedJsonNoUser, AuthReqRespDTO.class);
        assertAll(
                () -> assertThat(confirmResultFailedDtoNoUser.getStatusCode()).isEqualTo(404),
                () -> assertThat(confirmResultFailedDtoNoUser.getError()).isEqualTo("User not found")
        );
    }
}
