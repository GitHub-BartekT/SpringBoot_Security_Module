package pl.iseebugs.feature;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.util.StringUtils;
import pl.iseebugs.BaseIntegrationTest;
import pl.iseebugs.Security.infrastructure.security.projection.AuthReqRespDTO;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


class UserRegistersAndDeletesAccountIntegrationTest extends BaseIntegrationTest {

    @Test
    void should_user_registers_and_deletes_account() throws Exception {
    //Step 1: User tried to get JWT token by requesting POST /auth/signin
    //with username='someTestUser', password='somePassword' and system returned UNAUTHORIZED
        // given && when
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
        String confirmActionResultFailedJson = registerActionResultFailed.getResponse().getContentAsString();
        AuthReqRespDTO confirmResultFailedDto = objectMapper.readValue(confirmActionResultFailedJson, AuthReqRespDTO.class);
        assertAll(
                () -> assertThat(confirmResultFailedDto.getStatusCode()).isEqualTo(500),
                () -> assertThat(confirmResultFailedDto.getError()).isEqualTo("User not found")
        );


    //Step 2: User made GET /{some public endpoint} and system returned OK(200) with some public response
        // given && when
        ResultActions publicAccess = mockMvc.perform(get("/api/auth")
                .contentType(MediaType.APPLICATION_JSON)
        );

        //then
        publicAccess.andExpect(status().isOk())
                .andExpect(content().string("This is path with public access.".trim()));


    //Step 3: user made POST /api/auth/signup with username="someTestUser", password="someTestPassword"
    //and system registered user with status OK(200) and token="someToken"
        // given && when
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
                () -> assertThat(finalConfirmResultDto.getMessage()).isEqualTo("User created successfully"),
                () -> assertThat(finalConfirmResultDto.getToken()).isNotBlank()
        );

    //Step 4: user made POST /api/auth/confirm with token="someToken" and system responses with status OK(200)
        // given && when
        ResultActions confirmRegisterRequest = mockMvc.perform(post("/api/auth/confirm?token=" + registrationToken)
                .contentType(MediaType.APPLICATION_JSON_VALUE)
        );

        // then
        MvcResult confirmActionResult = confirmRegisterRequest.andExpect(status().isOk()).andReturn();
        String confirmActionResultJson = confirmActionResult.getResponse().getContentAsString();
        AuthReqRespDTO confirmResultDto = objectMapper.readValue(confirmActionResultJson, AuthReqRespDTO.class);

        assertAll(
                () -> assertThat(confirmResultDto.getStatusCode()).isEqualTo(200),
                () -> assertThat(confirmResultDto.getMessage()).isEqualTo("User confirmed")
        );


    //Step 5: user tried to get JWT token by requesting POST /api/auth/signin with username="someTestUser", password="someTestPassword"
    //and system returned OK(200) and token=AAAA.BBBB.CCC and refreshToken=DDDD.EEEE.FFF
        // given && when
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


    //Step 6: User made POST /api/auth/refresh with “Authorization: DDDD.EEEE.FFF
    // and system returned OK(200) and token=GGGG.HHHH.III and refreshToken=JJJJ.KKKK.LLL
        // given && when
         ResultActions refreshRegisterRequest = mockMvc.perform(post("/api/auth/refresh")
             .header("Authorization", "Bearer " + refreshToken)
             .contentType(MediaType.APPLICATION_JSON_VALUE)
        );

        // then
        MvcResult refreshActionResult = refreshRegisterRequest.andExpect(status().isOk()).andReturn();
        String refreshActionResultJson = refreshActionResult.getResponse().getContentAsString();
        AuthReqRespDTO refreshResultDto = objectMapper.readValue(refreshActionResultJson, AuthReqRespDTO.class);

        String newAccessToken = refreshResultDto.getToken();
        String newRefreshToken = refreshResultDto.getToken();

        //then
        assertAll(
                () -> assertThat(refreshResultDto.getStatusCode()).isEqualTo(200),
                () -> assertThat(refreshResultDto.getMessage()).isEqualTo("Successfully Refreshed Token"),
                () -> assertThat(refreshResultDto.getToken()).isNotBlank(),
                () -> assertThat(refreshResultDto.getRefreshToken()).isNotBlank(),
                () -> assertThat(StringUtils.countOccurrencesOf(newAccessToken, ".")).isEqualTo(2),
                () -> assertThat(StringUtils.countOccurrencesOf(newRefreshToken, ".")).isEqualTo(2)
        );


    //Step 7: User made POST /api/auth/updateUser with header “Authorization: GGGG.HHHH.III” and new data
    // and system returned OK(200)
        // given && when
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


    //Step 8: User made DELETE /api/auth/deleteUser with “Authorization: DDDD.EEEE.FFF”
    //and system returned OK(204)
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
    }
}
