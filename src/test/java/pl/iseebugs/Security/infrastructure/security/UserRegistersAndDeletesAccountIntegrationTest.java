package pl.iseebugs.Security.infrastructure.security;

import com.fasterxml.jackson.core.type.TypeReference;
import lombok.extern.java.Log;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.util.StringUtils;
import pl.iseebugs.Security.BaseIntegrationTest;
import pl.iseebugs.Security.domain.ApiResponse;
import pl.iseebugs.Security.domain.account.lifecycle.dto.AppUserDto;
import pl.iseebugs.Security.domain.account.lifecycle.dto.LoginResponse;
import pl.iseebugs.Security.domain.security.projection.LoginTokenDto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@Log
class UserRegistersAndDeletesAccountIntegrationTest extends BaseIntegrationTest {

    @Test
    void should_user_registers_changes_data_and_deletes_account() throws Exception {
    //Step 1: User tried to get JWT by requesting POST /auth/signin
    //with username='someTestUser', password='somePassword' and system returned UNAUTHORIZED
        // given && when
        log.info("Step 1. SignIn with bad credentials.");
        ResultActions failedLoginRequest = mockMvc.perform(post("/api/auth/signin")
                .content("""
                        {
                        "email": "some@mail.com",
                        "password": "somePassword"
                        }
                        """.trim())
                .contentType(MediaType.APPLICATION_JSON_VALUE)
        );

        // then
        MvcResult registerActionResultFailed = failedLoginRequest.andExpect(status().isOk()).andReturn();
        String registerActionResultFailedJson = registerActionResultFailed.getResponse().getContentAsString();
        ApiResponse<Void> confirmResultFailedDto = objectMapper.readValue(
                registerActionResultFailedJson, new TypeReference<>() {});
        assertAll(
                () -> assertThat(confirmResultFailedDto.getStatusCode()).isEqualTo(404),
                () -> assertThat(confirmResultFailedDto.getMessage()).isEqualTo("Email not found.")
        );


    //Step 2: User made GET /{some public endpoint} and system returned OK(200) and some public response
        // given && when
        log.info("Step 2. Open endpoint.");
        ResultActions publicAccess = mockMvc.perform(get("/api/auth")
                .contentType(MediaType.APPLICATION_JSON)
        );

        //then
        publicAccess.andExpect(status().isOk())
                .andExpect(content().string("This is path with public access.".trim()));


    //Step 3: user made POST /api/auth/signup with username="someTestUser", password="someTestPassword"
    //and system registered user with status OK(200) and register token="someToken"
        // given && when
        log.info("Step 3. SignUp with success.");
        ResultActions successRegisterRequest = mockMvc.perform(post("/api/auth/create/signup")
                .content("""
                        {
                        "email": "some@mail.com",
                        "password": "somePassword"
                        }
                        """.trim())
                .contentType(MediaType.APPLICATION_JSON_VALUE)
        );

        // then
        MvcResult registerActionResult = successRegisterRequest.andExpect(status().isOk()).andReturn();
        String registerActionResultJson = registerActionResult.getResponse().getContentAsString();
        ApiResponse<LoginTokenDto> registerResultDto = objectMapper.readValue(
                registerActionResultJson, new TypeReference<>() {});

        String registrationToken = registerResultDto.getData().token();

        final ApiResponse<LoginTokenDto> finalConfirmResultDto = registerResultDto;
        assertAll(
                () -> assertThat(registrationToken).isNotBlank(),
                () -> assertThat(finalConfirmResultDto.getData().expiresAt()).isNotNull()
        );



    // Step 4: user made POST /api/auth/confirm with token="invalidToken" and system responses with status FORBIDDEN(403)
        // given && when
        log.info("Step 4. Confirm token with invalid token");
        String badToken = "not.valid.token";
        ResultActions badConfirmTokenRegisterRequest = mockMvc.perform(get("/api/auth/create/confirm?token=" + badToken)
                .contentType(MediaType.APPLICATION_JSON_VALUE)
        );

        // then
        MvcResult badConfirmTokenActionResult = badConfirmTokenRegisterRequest.andExpect(status().isOk()).andReturn();
        String badConfirmTokenActionResultJson = badConfirmTokenActionResult.getResponse().getContentAsString();
        ApiResponse<Void> badConfirmTokenResultDto = objectMapper.readValue(
                badConfirmTokenActionResultJson, new TypeReference<>() {});
        assertAll(
                () -> assertThat(badConfirmTokenResultDto.getStatusCode()).isEqualTo(401),
                () -> assertThat(badConfirmTokenResultDto.getMessage()).isEqualTo("Token not found.")
        );


    //Step 5: user made POST /api/auth/confirm with token="someToken" and system responses with status OK(200)
        // given && when
        log.info("Step 5. Confirm token successfully");
        ResultActions confirmRegisterRequest = mockMvc.perform(get("/api/auth/create/confirm?token=" + registrationToken)
                .contentType(MediaType.APPLICATION_JSON_VALUE)
        );

        // then
        MvcResult confirmActionResult = confirmRegisterRequest
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Account successfully confirmed")) // Sprawdzenie treści odpowiedzi
                .andReturn();


    //Step 6: user tried to get JWT by requesting POST /api/auth/signin with username="someTestUser", password="someTestPassword"
    //and system returned OK(200) and accessToken=AAAA.BBBB.CCC and refreshToken=DDDD.EEEE.FFF
        // given && when
        log.info("Step 6. SignIn successfuly");
        ResultActions loginRequest = mockMvc.perform(post("/api/auth/signin")
                .content("""
                        {
                        "email": "some@mail.com",
                        "password": "somePassword"
                        }
                        """.trim())
                .contentType(MediaType.APPLICATION_JSON_VALUE)
        );


        // then
        MvcResult loginActionResult = loginRequest.andExpect(status().isOk()).andReturn();
        String loginActionResultJson = loginActionResult.getResponse().getContentAsString();
        ApiResponse<LoginResponse> loginResultDto = objectMapper.readValue(
                loginActionResultJson, new TypeReference<>() {});

        String accessToken = loginResultDto.getData().getAccessToken();
        String refreshToken = loginResultDto.getData().getRefreshToken();

        //then
        assertAll(
                () -> assertThat(accessToken).isNotBlank(),
                () -> assertThat(refreshToken).isNotBlank(),
                () -> assertThat(StringUtils.countOccurrencesOf(accessToken, ".")).isEqualTo(2),
                () -> assertThat(StringUtils.countOccurrencesOf(refreshToken, ".")).isEqualTo(2)
        );
    //Step 7: User made POST /api/auth/refresh with “Authorization: AAAA.BBBB.CCC” (access token)
    // and system returned UNAUTHORIZED(401)
        // given && when
        log.info("Step 7. Refresh access token with invalid token type.");
        ResultActions badRefreshRegisterRequest = mockMvc.perform(post("/api/auth/refresh")
                .header("Authorization", "Bearer " + accessToken)
                .contentType(MediaType.APPLICATION_JSON_VALUE)
        );

        // then
        MvcResult badRefreshActionResult = badRefreshRegisterRequest.andExpect(status().isUnauthorized()).andReturn();
        String badRefreshActionResultJson = badRefreshActionResult.getResponse().getContentAsString();
        ApiResponse<LoginResponse> badRefreshResultDto = objectMapper.readValue(
                badRefreshActionResultJson, new TypeReference<>() {});

        //then
        assertAll(
                () -> assertThat(badRefreshResultDto.getStatusCode()).isEqualTo(401),
                () -> assertThat(badRefreshResultDto.getMessage()).isEqualTo("Invalid or expired refresh token")
        );


    //Step 8: User made POST /api/auth/refresh with “Authorization: DDDD.EEEE.FFF (refresh token)
    // and system returned OK(200) and token=GGGG.HHHH.III and refreshToken=DDDD.EEEE.FFF
        // given && when
        log.info("Step 8. Refresh access token successfully");
        ResultActions refreshRegisterRequest = mockMvc.perform(post("/api/auth/refresh")
             .header("Authorization", "Bearer " + refreshToken)
             .contentType(MediaType.APPLICATION_JSON_VALUE)
        );

        // then
        MvcResult refreshActionResult = refreshRegisterRequest.andExpect(status().isOk()).andReturn();
        String refreshActionResultJson = refreshActionResult.getResponse().getContentAsString();
        ApiResponse<LoginResponse> refreshResultDto = objectMapper.readValue(
                refreshActionResultJson, new TypeReference<>() {});


        String newAccessToken = refreshResultDto.getData().getAccessToken();
        String newRefreshToken = refreshResultDto.getData().getRefreshToken();

        //then
        assertAll(
                () -> assertThat(newAccessToken).isNotBlank(),
                () -> assertThat(newRefreshToken).isNotBlank(),
                () -> assertThat(newRefreshToken.equals(refreshToken)),
                () -> assertThat(StringUtils.countOccurrencesOf(newAccessToken, ".")).isEqualTo(2),
                () -> assertThat(StringUtils.countOccurrencesOf(newRefreshToken, ".")).isEqualTo(2)
        );


    //Step 9: User made POST /api/auth/updateUser with header “Authorization: GGGG.HHHH.III” and new data
    // and system returned OK(200)
        // given && when
        log.info("Step 9.");
        ResultActions updateRegisterRequest = mockMvc.perform(patch("/api/auth/users")
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
        ApiResponse<AppUserDto> updateResultDto = objectMapper.readValue(
                updateActionResultJson, new TypeReference<>() {
                });
        AppUserDto result = updateResultDto.getData();

        assertAll(
                () -> assertThat(result.getEmail()).isEqualTo("some@mail.com"),
                () -> assertThat(result.getFirstName()).isEqualTo("Foo"),
                () -> assertThat(result.getLastName()).isEqualTo("Bar")
       );

    //Step 10:    User made DELETE /api/auth/deleteUser “Authorization: AAAA.BBBB.CCC” (refresh token)
    // and system returned UNAUTHORIZED(401)
        log.info("Step 10. Delete account with bad type token.");
        ResultActions badDeleteRegisterRequest = mockMvc.perform(delete("/api/auth/delete")
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
        ResultActions deleteRegisterRequest = mockMvc.perform(delete("/api/auth/delete")
                .header("Authorization", "Bearer " + newAccessToken)
                .contentType(MediaType.APPLICATION_JSON_VALUE)
        );

        // then
        MvcResult delete = deleteRegisterRequest.andExpect(status().isOk()).andReturn();
        String deleteActionResultJson = delete.getResponse().getContentAsString();
        ApiResponse<LoginTokenDto> deleteResultDto = objectMapper.readValue(deleteActionResultJson, new TypeReference<>() {
        });
        String deleteToken = deleteResultDto.getData().token();
        //then
        assertAll(
                () -> assertThat(deleteResultDto.getStatusCode()).isEqualTo(201),
                () -> assertThat(deleteResultDto.getMessage()).isEqualTo("Delete confirmation mail created successfully.")
       );


    //Step 12: User made GET /api/auth/delete-confirm?token= with “Authorization: AAAA.BBBB.CCC”
    //and system returned OK(204)
        log.info("Step 12.");
        ResultActions confirmationDeleteRegisterRequest = mockMvc.perform(get("/api/auth/delete/delete-confirm?token=" + deleteToken)
                .header("Authorization", "Bearer " + newAccessToken)
                .contentType(MediaType.APPLICATION_JSON_VALUE)
        );

        // then
        MvcResult deletedAccount = confirmationDeleteRegisterRequest.andExpect(status().isOk()).andReturn();
        String deletedAccountActionResultJson = deletedAccount.getResponse().getContentAsString();
        ApiResponse<LoginTokenDto> deletedAccountResultDto = objectMapper.readValue(deletedAccountActionResultJson, new TypeReference<>() {
        });
        //then
        assertAll(
                () -> assertThat(deletedAccountResultDto.getStatusCode()).isEqualTo(204),
                () -> assertThat(deletedAccountResultDto.getMessage()).isEqualTo("User account successfully deleted.")
        );

    //Step 13: User tried to get JWT by requesting POST /auth/signin
    //with username='someTestUser', password='somePassword' and system returned UNAUTHORIZED
        // given && when
        log.info("Step 13.");
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
        ApiResponse<Void> confirmResultFailedDtoNoUser = objectMapper.readValue(
                confirmActionResultFailedJsonNoUser, new TypeReference<>() {});
        assertAll(
                () -> assertThat(confirmResultFailedDtoNoUser.getStatusCode()).isEqualTo(404),
                () -> assertThat(confirmResultFailedDtoNoUser.getMessage()).isEqualTo("Email not found.")
        );
    }
}
