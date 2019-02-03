package br.com.lbcoutinho.auth.security.exception;

import org.springframework.security.core.AuthenticationException;

public class JWTValidationException extends AuthenticationException {
    public JWTValidationException(String msg) {
        super(msg);
    }
}
