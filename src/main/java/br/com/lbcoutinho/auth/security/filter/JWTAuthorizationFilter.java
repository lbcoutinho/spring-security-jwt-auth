package br.com.lbcoutinho.auth.security.filter;

import br.com.lbcoutinho.auth.security.authentication.JWTAuthenticationToken;
import br.com.lbcoutinho.auth.security.dto.MessageResponse;
import br.com.lbcoutinho.auth.security.exception.JWTNotFoundException;
import br.com.lbcoutinho.auth.security.exception.JWTValidationException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static br.com.lbcoutinho.auth.security.util.SecurityConstants.*;

/**
 * Validates JWT token on every request
 */
// TODO move this to gateway
@Slf4j
public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    private ObjectMapper objectMapper;

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager, ObjectMapper objectMapper) {
        super(authenticationManager);
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        log.trace("JWTAuthorizationFilter.doFilterInternal");
        String header = request.getHeader(HEADER_AUTHORIZATION);
        log.debug("JWT Authorization - Header = {}", header);

        // Authorization header value must start with "Bearer "
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            try {
                // Decode/verify JWT token and extract user login
                String login = JWT.require(Algorithm.HMAC512(JWT_SECRET))
                        .build()
                        .verify(header.replace(BEARER_PREFIX, ""))
                        .getSubject();

                log.debug("JWT is valid - login = {}", login);

                if (login != null) {
                    // TODO get other info from JWT and add to JWTAuthenticationToken
                    JWTAuthenticationToken authentication = new JWTAuthenticationToken(login);
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    onSuccessfulAuthentication(request, response, authentication);
                    // Request is forward only if authorization is successful
                    chain.doFilter(request, response);
                }
            } catch (JWTVerificationException e) {
                log.debug("{}: {}", e.getClass().getCanonicalName(), e.getMessage());
                String msg;
                if (e instanceof TokenExpiredException) {
                    msg = "JWT expired";
                } else if (e instanceof JWTDecodeException) {
                    msg = "Invalid JWT";
                } else {
                    msg = e.getMessage();
                }

                onUnsuccessfulAuthentication(request, response, new JWTValidationException(msg));
            }
        } else {
            onUnsuccessfulAuthentication(request, response, new JWTNotFoundException("Authorization header not found"));
        }
    }

    @Override
    protected void onSuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, Authentication authResult) throws IOException {
        log.trace("JWTAuthorizationFilter.onSuccessfulAuthentication");
        log.debug("SecurityContext set for user = {}", authResult.getPrincipal().toString());
        SecurityContextHolder.getContext().setAuthentication(authResult);
    }

    @Override
    protected void onUnsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException {
        log.trace("JWTAuthorizationFilter.onUnsuccessfulAuthentication");
        log.debug("Authorization failure - {} / {} ", e.getClass().getCanonicalName(), e.getMessage());
        int status = e instanceof JWTNotFoundException ? HttpStatus.FORBIDDEN.value() : HttpStatus.UNAUTHORIZED.value();

        response.setStatus(status);
        response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(), new MessageResponse(e.getMessage()));
    }

}
