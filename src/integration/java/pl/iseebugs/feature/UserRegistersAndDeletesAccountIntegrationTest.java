package pl.iseebugs.feature;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;
import pl.iseebugs.BaseIntegrationTest;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


class UserRegistersAndDeletesAccountIntegrationTest extends BaseIntegrationTest {

    @Test
    void should_user_registers_and_deletes_account() throws Exception {
    //Step 1: User tried to get JWT token by requesting POST /auth/signin
    //with username='someTestUser', password='somePassword' and system returned UNAUTHORIZED
        // given && then
        ResultActions failedLoginRequest = mockMvc.perform(post("/api/auth/signIn")
                .content("""
                {
                "username": "someTestUser",
                "password": "somePassword"
                }
                """.trim())
                .contentType(MediaType.APPLICATION_JSON_VALUE)
        );
        // then
        failedLoginRequest
                .andExpect(status().isForbidden());

    //Step 2: User made GET /{some public endpoint} and system returned OK(200) with some public response
    

    //Step 3: user made POST /api/auth/signup with username="someTestUser", password="someTestPassword"
    //and system registered user with status OK(200) and token="someToken"


    //Step 4: user made POST /api/auth/confirm with token="someToken" and system responses with status OK(200)


    //Step 5: user tried to get JWT token by requesting POST /api/auth/signin with username="someTestUser", password="someTestPassword"
    //and system returned OK(200) and token=AAAA.BBBB.CCC and refreshToken=DDDD.EEEE.FFF


    //Step 6: User made POST /api/auth/updateUser with header “Authorization: AAAA.BBBB.CCC” and body username='notMyName'
    //and system returned OK(200)


    //Step 7: User made POST /api/auth/refresh with “Authorization: DDDD.EEEE.FFF”
    //and system returned OK(200) and token=GGGG.HHHH.III and refreshToken=JJJJ.KKKK.LLL


    //Step 8: User made DELETE /api/auth/deleteUser with “Authorization: DDDD.EEEE.FFF”
    //and system returned OK(204)
    }
}
