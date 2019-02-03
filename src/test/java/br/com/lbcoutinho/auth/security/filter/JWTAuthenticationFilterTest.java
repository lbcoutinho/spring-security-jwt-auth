package br.com.lbcoutinho.auth.security.filter;

import br.com.lbcoutinho.auth.model.ApplicationUser;
import br.com.lbcoutinho.auth.security.authentication.JWTAuthenticationToken;
import br.com.lbcoutinho.auth.security.dto.MessageResponse;
import br.com.lbcoutinho.auth.security.dto.UserCredentials;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.json.JacksonTester;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.DelegatingServletInputStream;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;

import static br.com.lbcoutinho.auth.security.util.SecurityConstants.BEARER_PREFIX;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@ExtendWith(SpringExtension.class)
class JWTAuthenticationFilterTest {

    private static JWTAuthenticationFilter filter;
    private static AuthenticationManager authenticationManager;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MockFilterChain chain;

    JacksonTester<MessageResponse> jsonMessageResponse;
    JacksonTester<UserCredentials> jsonUserCredentials;

    @BeforeAll
    static void beforeAll() {
        authenticationManager = mock(AuthenticationManager.class);
        filter = new JWTAuthenticationFilter(authenticationManager, new ObjectMapper());
    }

    @BeforeEach
    void beforeEach() {
        // Initializes the JacksonTester
        JacksonTester.initFields(this, new ObjectMapper());

        request = mock(MockHttpServletRequest.class);
        response = new MockHttpServletResponse();
        chain = mock(MockFilterChain.class);

        given(request.getServletPath()).willReturn("/login");
    }

    @Test
    void givenFinishedInputStream_whenDoFilter_thenResponseStatusIs401() throws IOException, ServletException {
        // Given
        ServletInputStream inputStream = mock(ServletInputStream.class);
        given(inputStream.isFinished()).willReturn(true);
        given(request.getInputStream()).willReturn(inputStream);

        // When
        filter.doFilter(request, response, chain);

        // Then
        assertAll(
                () -> assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value()),
                () -> assertThat(response.getHeader(HttpHeaders.CONTENT_TYPE)).isEqualTo(MediaType.APPLICATION_JSON_VALUE),
                () -> assertThat(response.getContentAsString())
                        .isEqualTo(jsonMessageResponse.write(new MessageResponse("Missing credentials")).getJson())
        );

        verify(request).getInputStream();
        verifyZeroInteractions(chain);
    }

    @Test
    void givenInvalidRequestContent_whenDoFilter_thenResponseStatusIs500() throws IOException, ServletException {
        // Given
        DelegatingServletInputStream inputStream = new DelegatingServletInputStream(
                new ByteArrayInputStream("{\"invalid\":\"text\", \"password\":\"123\"}".getBytes())
        );
        given(request.getInputStream()).willReturn(inputStream);

        // When
        filter.doFilter(request, response, chain);

        // Then
        assertAll(
                () -> assertThat(response.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value()),
                () -> assertThat(response.getHeader(HttpHeaders.CONTENT_TYPE)).isEqualTo(MediaType.APPLICATION_JSON_VALUE),
                () -> assertThat(response.getContentAsString())
                        .isEqualTo(jsonMessageResponse.write(new MessageResponse("Error reading user credentials")).getJson())
        );

        verify(request).getInputStream();
        verifyZeroInteractions(chain);
    }

    @Test
    void givenValidCredentials_whenDoFilter_thenResponseStatusIs200() throws IOException, ServletException {
        // Given
        UserCredentials credentials = new UserCredentials("user", "12345");
        DelegatingServletInputStream inputStream = new DelegatingServletInputStream(
                new ByteArrayInputStream(jsonUserCredentials.write(credentials).getJson().getBytes())
        );
        given(request.getInputStream()).willReturn(inputStream);

        ApplicationUser user = new ApplicationUser();
        user.setLogin(credentials.getLogin());
        given(authenticationManager.authenticate(new JWTAuthenticationToken(credentials))).willReturn(new JWTAuthenticationToken(user));

        // When
        filter.doFilter(request, response, chain);

        // Then
        assertAll(
                () -> assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value()),
                () -> assertThat(response.getHeader(HttpHeaders.CONTENT_TYPE)).isEqualTo(MediaType.APPLICATION_JSON_VALUE),
                () -> assertThat(response.getContentAsString())
                        .isEqualTo(jsonMessageResponse.write(new MessageResponse("Login successful! JWT token set on Authorization header.")).getJson()),
                () -> assertThat(response.getHeader(AUTHORIZATION)).startsWith(BEARER_PREFIX)
        );

        verify(request).getInputStream();
        verifyZeroInteractions(chain);
    }

}
