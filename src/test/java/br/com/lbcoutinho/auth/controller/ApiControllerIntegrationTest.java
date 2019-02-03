package br.com.lbcoutinho.auth.controller;

import br.com.lbcoutinho.auth.security.dto.MessageResponse;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;

import java.util.Base64;
import java.util.Date;

import static br.com.lbcoutinho.auth.model.Authority.USER;
import static br.com.lbcoutinho.auth.security.util.SecurityConstants.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

/**
 * In this Integration Test, Spring will load the entire application context.<br>
 * With the {@link SpringBootTest} annotation the context is autoconfigured and the web server is started in a random port.<br>
 * The {@link TestRestTemplate} class is used here to perform real requests to the server.
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
class ApiControllerIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void givenNoAuthorization_whenGetWelcome_thenResponseStatusIs403() {
        // When
        ResponseEntity<String> response = restTemplate.getForEntity("/welcome", String.class);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void givenInvalidJwt_whenGetWelcome_thenResponseStatusIs401() {
        // Given
        HttpHeaders headers = new HttpHeaders();
        headers.add(AUTHORIZATION, "Bearer 123");
        HttpEntity<String> httpEntity = new HttpEntity<>(headers);

        // When
        ResponseEntity<MessageResponse> response = restTemplate.exchange("/welcome", HttpMethod.GET, httpEntity, MessageResponse.class);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).isEqualTo(new MessageResponse("Invalid JWT"));
    }

    @Test
    void givenExpiredJwt_whenGetWelcome_thenResponseStatusIs401() {
        // Given
        String jwt = BEARER_PREFIX + JWT.create()
                .withSubject("user")
                .withArrayClaim(AUTHORITIES, new String[]{USER.toString()})
                .withExpiresAt(new Date(System.currentTimeMillis() - EXPIRATION_TIME))
                .sign(Algorithm.HMAC512(JWT_SECRET));
        HttpHeaders headers = new HttpHeaders();
        headers.add(AUTHORIZATION, jwt);
        HttpEntity<String> httpEntity = new HttpEntity<>(headers);

        // When
        ResponseEntity<MessageResponse> response = restTemplate.exchange("/welcome", HttpMethod.GET, httpEntity, MessageResponse.class);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).isEqualTo(new MessageResponse("JWT expired"));
    }

    @Test
    void givenValidJwt_whenGetWelcome_thenResponseStatusIs200() {
        // Given
        String jwt = BEARER_PREFIX + JWT.create()
                .withSubject("user")
                .withArrayClaim(AUTHORITIES, new String[]{USER.toString()})
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .sign(Algorithm.HMAC512(JWT_SECRET));
        HttpHeaders headers = new HttpHeaders();
        headers.add(AUTHORIZATION, jwt);
        HttpEntity<String> httpEntity = new HttpEntity<>(headers);

        // When
        ResponseEntity<String> response = restTemplate.exchange("/welcome", HttpMethod.GET, httpEntity, String.class);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo("Welcome to the API user. You're using Bearer authorization.");
    }

    @Test
    void givenWrongBasicCredentials_whenGetBasicWelcome_thenResponseStatusIs401() {
        // Given
        String credentials = BASIC_PREFIX + Base64.getEncoder().encodeToString("user1:wrong-password".getBytes());
        HttpHeaders headers = new HttpHeaders();
        headers.add(AUTHORIZATION, credentials);
        HttpEntity<String> httpEntity = new HttpEntity<>(headers);

        // When
        ResponseEntity<String> response = restTemplate.exchange("/basic/welcome", HttpMethod.GET, httpEntity, String.class);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void givenCorrectBasicCredentials_whenGetBasicWelcome_thenResponseStatusIs200() {
        // Given
        String credentials = BASIC_PREFIX + Base64.getEncoder().encodeToString("user1:12345".getBytes());
        HttpHeaders headers = new HttpHeaders();
        headers.add(AUTHORIZATION, credentials);
        HttpEntity<String> httpEntity = new HttpEntity<>(headers);

        // When
        ResponseEntity<String> response = restTemplate.exchange("/basic/welcome", HttpMethod.GET, httpEntity, String.class);
        System.out.println("response = " + response);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo("Welcome to the API user1. You're using Basic authorization.");
    }

}
