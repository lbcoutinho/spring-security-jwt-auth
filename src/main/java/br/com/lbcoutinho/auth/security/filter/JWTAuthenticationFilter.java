package br.com.lbcoutinho.auth.security.filter;

import br.com.lbcoutinho.auth.security.authentication.JWTAuthenticationToken;
import br.com.lbcoutinho.auth.security.config.WebSecurityConfig;
import br.com.lbcoutinho.auth.security.dto.UserCredentials;
import br.com.lbcoutinho.auth.security.handler.JWTAuthenticationHandler;
import br.com.lbcoutinho.auth.security.service.UserServiceAuthenticationProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

import static br.com.lbcoutinho.auth.security.util.SecurityConstants.*;

/**
 * Handler for /login endpoint and generates JWT token if login is successful.
 */
@Slf4j
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private ObjectMapper objectMapper;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager, JWTAuthenticationHandler JWTAuthenticationHandler, ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;

        setAuthenticationFailureHandler(JWTAuthenticationHandler::onAuthenticationFailure);
        setAuthenticationSuccessHandler(JWTAuthenticationHandler::onAuthenticationSuccess);
        setAuthenticationManager(authenticationManager);
        // /login is already the default authentication endpoint, but I'm leaving here as example
        setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/login", "POST"));
    }

    /**
     * This method immediately invoked when user sends POST request to /login
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.trace("JWTAuthenticationFilter.attemptAuthentication");
        try {
            // Check if request body has content
            ServletInputStream requestBody = request.getInputStream();
            if (requestBody.isFinished()) {
                throw new AuthenticationCredentialsNotFoundException("Missing credentials");
            }

            // Read request body into an UserCredentials object
            UserCredentials credentials = objectMapper.readValue(requestBody, UserCredentials.class);
            log.debug("Authentication attempt - credentials = {}", credentials);

            /**
             * Delegates the authentication to {@link UserServiceAuthenticationProvider} that was setup on {@link WebSecurityConfig#configure(AuthenticationManagerBuilder)}
             */
            return getAuthenticationManager().authenticate(new JWTAuthenticationToken(credentials.getLogin(), credentials.getPassword()));
        } catch (IOException e) {
            throw new AuthenticationServiceException("Error reading user credentials", e);
        }
    }


    /**
     * This method is invoked if [@link {@link AuthenticationManager#authenticate(Authentication)} is successful.
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) {
        log.trace("JWTAuthenticationFilter.successfulAuthentication");

        JWTAuthenticationToken user = (JWTAuthenticationToken) authResult;
        log.debug("Authentication successful - Generating JWT token for user {}", user.getLogin());

        // Create JWT token
        String token = JWT.create()
                .withSubject(user.getLogin())
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .sign(Algorithm.HMAC512(JWT_SECRET));

        // Set token on response header
        response.addHeader(HEADER_AUTHORIZATION, BEARER_PREFIX + token);
    }
}
