package br.com.lbcoutinho.auth.security.filter;

import br.com.lbcoutinho.auth.model.Authority;
import br.com.lbcoutinho.auth.security.authentication.JWTAuthenticationToken;
import br.com.lbcoutinho.auth.security.dto.MessageResponse;
import br.com.lbcoutinho.auth.security.exception.JWTNotFoundException;
import br.com.lbcoutinho.auth.security.exception.JWTValidationException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static br.com.lbcoutinho.auth.security.util.SecurityConstants.*;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

/**
 * Validates JWT token on every request
 */
@Slf4j
public class JWTAuthorizationFilter extends OncePerRequestFilter {

    private ObjectMapper objectMapper;

    public JWTAuthorizationFilter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        log.trace("JWTAuthorizationFilter.doFilterInternal");
        String header = request.getHeader(AUTHORIZATION);
        log.debug("JWT Authorization - Header = {}", header);

        // Authorization header value must start with "Bearer "
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            try {
                // Decode/verify JWT token and extract user login
                DecodedJWT decodedJwt = JWT.require(Algorithm.HMAC512(JWT_SECRET)).build()
                        .verify(header.replace(BEARER_PREFIX, ""));

                log.debug("JWT is valid - login = {}", decodedJwt.getSubject());

                // Extract authorities from decoded JWT and add to set
                Set<Authority> authorities = Arrays.stream(decodedJwt.getClaim(AUTHORITIES).asArray(String.class)).map(Authority::valueOf).collect(Collectors.toSet());

                JWTAuthenticationToken authentication = new JWTAuthenticationToken(decodedJwt, authorities);
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                log.debug("Updating SecurityContextHolder to contain: {}", authentication);
                SecurityContextHolder.getContext().setAuthentication(authentication);

                // Request is forward only if authorization is successful
                chain.doFilter(request, response);

            } catch (JWTVerificationException e) {
                log.debug("{}: {}", e.getClass().getSimpleName(), e.getMessage());
                String msg = e.getMessage();
                if (e instanceof TokenExpiredException) {
                    msg = "JWT expired";
                } else if (e instanceof JWTDecodeException) {
                    msg = "Invalid JWT";
                }

                onUnsuccessfulAuthentication(response, new JWTValidationException(msg));
            }
        } else {
            onUnsuccessfulAuthentication(response, new JWTNotFoundException("Authorization header not found"));
        }
    }

    private void onUnsuccessfulAuthentication(HttpServletResponse response, AuthenticationException e) throws IOException {
        log.trace("JWTAuthorizationFilter.onUnsuccessfulAuthentication");
        log.debug("Authorization failure - {} / {} ", e.getClass().getSimpleName(), e.getMessage());
        int status = e instanceof JWTNotFoundException ? HttpStatus.FORBIDDEN.value() : HttpStatus.UNAUTHORIZED.value();

        response.setStatus(status);
        response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(), new MessageResponse(e.getMessage()));
    }

}
