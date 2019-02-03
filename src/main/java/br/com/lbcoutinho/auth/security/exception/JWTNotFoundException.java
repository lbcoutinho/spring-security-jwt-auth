package br.com.lbcoutinho.auth.security.exception;

import org.springframework.security.core.AuthenticationException;

public class JWTNotFoundException extends AuthenticationException {
    public JWTNotFoundException(String msg) {
        super(msg);
    }
}
