package br.com.lbcoutinho.auth.controller;

import br.com.lbcoutinho.auth.security.dto.MessageResponse;
import br.com.lbcoutinho.auth.security.service.UserAuthenticationProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.json.JacksonTester;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Date;

import static br.com.lbcoutinho.auth.model.Authority.ADMIN;
import static br.com.lbcoutinho.auth.model.Authority.USER;
import static br.com.lbcoutinho.auth.security.util.SecurityConstants.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.is;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * In this Integration Test, Spring will load the application context only a partially.<br>
 * With the {@link WebMvcTest} annotation the {@link MockMvc} instance gets autoconfigured and available in the context.
 * Since {@link AdminController} is specified on the annotation, all the surrounding configurations related to this controller will also get loaded like filters and controller advisors.<br>
 * We can inject beans on the context by using the {@link MockBean} annotation.<br>
 * The request and response used here are mocks using the classes {@link MockHttpServletRequest} and {@link MockHttpServletResponse}.
 */
@WebMvcTest(AdminController.class)
class AdminControllerIntegrationTest {

    @Autowired
    MockMvc mvc;

    @MockBean
    UserAuthenticationProvider userAuthenticationProvider;

    JacksonTester<MessageResponse> jsonMessageResponse;

    @BeforeEach
    void setup() {
        // Initializes the JacksonTester
        JacksonTester.initFields(this, new ObjectMapper());
    }

    @Test
    void givenNoAuthorization_whenGetAdminWelcome_thenResponseStatusIs403() throws Exception {
        // When
        MockHttpServletResponse response = mvc.perform(get("/admin/welcome")).andReturn().getResponse();

        // Then - Assertion using AssertJ
        assertThat(response.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(response.getContentAsString())
                .isEqualTo(jsonMessageResponse.write(new MessageResponse("Authorization header not found")).getJson());
    }

    @Test
    void givenInvalidJwt_whenGetAdminWelcome_thenResponseStatusIs401() throws Exception {
        // Given
        String invalidJwt = "Bearer 123";

        // When
        MockHttpServletResponse response = mvc.perform(get("/admin/welcome")
                .header(AUTHORIZATION, invalidJwt))
                .andReturn().getResponse();

        // Then
        assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(response.getContentAsString())
                .isEqualTo(jsonMessageResponse.write(new MessageResponse("Invalid JWT")).getJson());
    }

    @Test
    void givenExpiredJwt_whenGetAdminWelcome_thenResponseStatusIs401() throws Exception {
        // Given
        String expiredJwt = BEARER_PREFIX + JWT.create()
                .withSubject("user")
                .withArrayClaim(AUTHORITIES, new String[]{USER.toString()})
                .withExpiresAt(new Date(System.currentTimeMillis() - EXPIRATION_TIME))
                .sign(Algorithm.HMAC512(JWT_SECRET));

        // When - Assertion using MockMvc
        mvc.perform(get("/admin/welcome")
                .header(AUTHORIZATION, expiredJwt))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message", is("JWT expired")));
    }

    @Test
    void givenJwtWithoutAdminAuthority_whenGetAdminWelcome_thenResponseStatusIs403() throws Exception {
        // Given
        String jwt = BEARER_PREFIX + JWT.create()
                .withSubject("user")
                .withArrayClaim(AUTHORITIES, new String[]{USER.toString()})
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .sign(Algorithm.HMAC512(JWT_SECRET));

        // When
        mvc.perform(get("/admin/welcome")
                .header(AUTHORIZATION, jwt))
                .andExpect(status().isForbidden());
    }

    @Test
    void givenJwtWithAdminAuthority_whenGetAdminWelcome_thenResponseStatusIs200() throws Exception {
        // Given
        String token = JWT.create()
                .withSubject("admin")
                .withArrayClaim(AUTHORITIES, new String[]{USER.toString(), ADMIN.toString()})
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .sign(Algorithm.HMAC512(JWT_SECRET));

        // When
        MockHttpServletResponse response = mvc.perform(get("/admin/welcome")
                .header(AUTHORIZATION, BEARER_PREFIX + token))
                .andReturn().getResponse();

        // Then
        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
        assertThat(response.getContentAsString())
                .isEqualTo("Welcome Admin API admin. You're using Bearer authorization.");
    }

}
