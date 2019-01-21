package br.com.lbcoutinho.auth.security.handler;

import br.com.lbcoutinho.auth.security.dto.MessageResponse;
import br.com.lbcoutinho.auth.security.filter.JWTAuthenticationFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Handler for success and failure on {@link JWTAuthenticationFilter}.
 */
@Component
@Slf4j
public class JWTAuthenticationHandler implements AuthenticationSuccessHandler, AuthenticationFailureHandler {

    private ObjectMapper objectMapper;

    @Autowired
    public JWTAuthenticationHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {
        log.trace("CustomAuthenticationHandler.onAuthenticationSuccess - OK");
        // Default success handler also returns OK, but I'm redefining here just as example
        response.setStatus(HttpStatus.OK.value());
        response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(), new MessageResponse("Login successful!"));
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException e)
            throws IOException {
        log.trace("CustomAuthenticationHandler.onAuthenticationFailure");
        log.debug("Authentication failure - {} / {} ", e.getClass().getCanonicalName(), e.getMessage());

        if (e instanceof AuthenticationServiceException) {
            response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        } else {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
        }

        response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(), new MessageResponse(e.getMessage()));
    }

}
