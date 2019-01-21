package br.com.lbcoutinho.auth.security.authentication;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.Collections;

/**
 * An Authentication implementation that is designed to store user login, password and JWT claims.
 */
public class JWTAuthenticationToken extends UsernamePasswordAuthenticationToken {

    public JWTAuthenticationToken(String login, String password) {
        super(login, password);
    }

    public JWTAuthenticationToken(String login) {
        super(login, null, Collections.emptyList());
    }

    public String getLogin() {
        return getPrincipal().toString();
    }

    public String getPassword() {
        return getCredentials().toString();
    }
}
