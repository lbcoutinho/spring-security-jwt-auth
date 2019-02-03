package br.com.lbcoutinho.auth.security.filter;

import br.com.lbcoutinho.auth.security.dto.MessageResponse;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.json.JacksonTester;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import javax.servlet.ServletException;
import java.io.IOException;
import java.util.Date;
import java.util.stream.Stream;

import static br.com.lbcoutinho.auth.model.Authority.USER;
import static br.com.lbcoutinho.auth.security.util.SecurityConstants.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@ExtendWith(SpringExtension.class)
class JWTAuthorizationFilterTest {

    private static JWTAuthorizationFilter filter;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MockFilterChain chain;

    JacksonTester<MessageResponse> jsonMessageResponse;

    @BeforeAll
    static void beforeAll() {
        filter = new JWTAuthorizationFilter(new ObjectMapper());
    }

    @BeforeEach
    void beforeEach() {
        // Initializes the JacksonTester
        JacksonTester.initFields(this, new ObjectMapper());

        request = mock(MockHttpServletRequest.class);
        response = new MockHttpServletResponse();
        chain = mock(MockFilterChain.class);

        given(request.getServletPath()).willReturn("/anything");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "Basic 123"})
    void givenNoBearerAuthorization_whenDoFilter_thenResponseStatusIs403(String header) throws ServletException, IOException {
        // Given
        if (!header.isEmpty()) {
            given(request.getHeader(AUTHORIZATION)).willReturn(header);
        }

        // When
        filter.doFilter(request, response, chain);

        // Then
        assertAll(
                () -> assertThat(response.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value()),
                () -> assertThat(response.getHeader(HttpHeaders.CONTENT_TYPE)).isEqualTo(MediaType.APPLICATION_JSON_VALUE),
                () -> assertThat(response.getContentAsString())
                        .isEqualTo(jsonMessageResponse.write(new MessageResponse("Authorization header not found")).getJson())
        );

        // Verify interactions with mocks
        verify(request).getHeader(AUTHORIZATION);
        verifyZeroInteractions(chain);
    }

    @ParameterizedTest
    @MethodSource("invalidJwtGenerator")
    void givenInvalidJwt_whenDoFilter_thenResponseStatusIs401(String header, MessageResponse errorMessage) throws ServletException, IOException {
        // Given
        given(request.getHeader(AUTHORIZATION)).willReturn(header);

        // When
        filter.doFilter(request, response, chain);

        // Then
        assertAll(
                () -> assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value()),
                () -> assertThat(response.getHeader(HttpHeaders.CONTENT_TYPE)).isEqualTo(MediaType.APPLICATION_JSON_VALUE),
                () -> assertThat(response.getContentAsString()).isEqualTo(jsonMessageResponse.write(errorMessage).getJson())
        );

        // Verify interactions with mocks
        verify(request).getHeader(AUTHORIZATION);
        verifyZeroInteractions(chain);
    }

    private static Stream<Arguments> invalidJwtGenerator() {
        String expiredJwt = JWT.create()
                .withSubject("user")
                .withArrayClaim(AUTHORITIES, new String[]{USER.toString()})
                .withExpiresAt(new Date(System.currentTimeMillis() - EXPIRATION_TIME))
                .sign(Algorithm.HMAC512(JWT_SECRET));

        return Stream.of(
                Arguments.of(BEARER_PREFIX + expiredJwt, new MessageResponse("JWT expired")),
                Arguments.of(BEARER_PREFIX + "invalid", new MessageResponse("Invalid JWT")));
    }

    @Test
    void givenValidJwt_whenDoFilter_thenResponseStatusIs200() throws ServletException, IOException {
        // Given
        String jwt = BEARER_PREFIX + JWT.create()
                .withSubject("user")
                .withArrayClaim(AUTHORITIES, new String[]{USER.toString()})
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .sign(Algorithm.HMAC512(JWT_SECRET));
        given(request.getHeader(AUTHORIZATION)).willReturn(jwt);

        // When
        filter.doFilter(request, response, chain);

        // Then - verify interactions with mocks
        verify(request).getHeader(AUTHORIZATION);
        verify(chain).doFilter(request, response);
    }
}

