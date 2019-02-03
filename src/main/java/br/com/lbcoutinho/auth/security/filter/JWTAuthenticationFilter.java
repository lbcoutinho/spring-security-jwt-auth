package br.com.lbcoutinho.auth.security.filter;

import br.com.lbcoutinho.auth.model.ApplicationUser;
import br.com.lbcoutinho.auth.model.Authority;
import br.com.lbcoutinho.auth.security.authentication.JWTAuthenticationToken;
import br.com.lbcoutinho.auth.security.config.WebSecurityConfig;
import br.com.lbcoutinho.auth.security.dto.MessageResponse;
import br.com.lbcoutinho.auth.security.dto.UserCredentials;
import br.com.lbcoutinho.auth.security.service.UserAuthenticationProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

import static br.com.lbcoutinho.auth.security.util.SecurityConstants.*;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

/**
 * Handler for /login endpoint and generates JWT token if login is successful.
 */
@Slf4j
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter implements AuthenticationFailureHandler {

    private ObjectMapper objectMapper;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager, ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;

        setAuthenticationFailureHandler(this::onAuthenticationFailure);
        setAuthenticationManager(authenticationManager);
        // /login is already the default authentication route, but I'm leaving here as example
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
             * Delegates the authentication to {@link UserAuthenticationProvider} that was setup on {@link WebSecurityConfig#configure(AuthenticationManagerBuilder)}
             */
            return getAuthenticationManager().authenticate(new JWTAuthenticationToken(credentials));
        } catch (IOException e) {
            throw new AuthenticationServiceException("Error reading user credentials", e);
        }
    }


    /**
     * This method is invoked if [@link {@link AuthenticationManager#authenticate(Authentication)} is successful.
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException {
        log.trace("JWTAuthenticationFilter.successfulAuthentication");
        log.debug("Authentication success. Updating SecurityContextHolder to contain: {}", authResult);
        SecurityContextHolder.getContext().setAuthentication(authResult);

        ApplicationUser user = ((JWTAuthenticationToken) authResult).getUser();
        log.debug("Generating JWT token for user {}", user.getLogin());

        // Create JWT token
        String[] authorities = user.getAuthorities().stream().map(Authority::toString).toArray(String[]::new);
        String token = JWT.create()
                .withSubject(user.getLogin())
                .withClaim(NAME, user.getName())
                .withClaim(EMAIL, user.getEmail())
                .withClaim(PHONE, user.getPhone())
                .withArrayClaim(AUTHORITIES, authorities)
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .sign(Algorithm.HMAC512(JWT_SECRET));

        // Set token on response header
        response.addHeader(AUTHORIZATION, BEARER_PREFIX + token);

        response.setStatus(HttpStatus.OK.value());
        response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(), new MessageResponse("Login successful! JWT token set on Authorization header."));
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException e)
            throws IOException {
        log.trace("CustomAuthenticationHandler.onAuthenticationFailure");
        log.debug("Authentication failure - {} / {} ", e.getClass().getSimpleName(), e.getMessage());

        if (e instanceof AuthenticationServiceException)
            response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        else response.setStatus(HttpStatus.UNAUTHORIZED.value());

        response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(), new MessageResponse(e.getMessage()));
    }

}
