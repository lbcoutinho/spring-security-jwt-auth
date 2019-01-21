package br.com.lbcoutinho.auth.security.service;

import br.com.lbcoutinho.auth.security.authentication.JWTAuthenticationToken;
import br.com.lbcoutinho.auth.security.dto.UserDetails;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Retrieves user details from User Service and performs password comparison.
 */
@Service
@Slf4j
public class UserServiceAuthenticationProvider implements AuthenticationProvider {

    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    public UserServiceAuthenticationProvider(BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String login = authentication.getName();
        String password = authentication.getCredentials().toString();
        log.trace("UserServiceAuthenticationProvider.authenticate - login={} / password={}", login, password);

        UserDetails userDetails = getUserDetails(login);
        if (bCryptPasswordEncoder.matches(password, userDetails.getPassword())) {
            log.trace("Password matches - returning UsernamePasswordAuthenticationToken");
            return new JWTAuthenticationToken(login);
        } else {
            throw new BadCredentialsException("Incorrect password");
        }
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return UsernamePasswordAuthenticationToken.class.equals(aClass);
    }

    private UserDetails getUserDetails(String login) throws AuthenticationException {
        if (login.equals("admin")) {
            // Username = admin / Password = 12345
            return new UserDetails("admin", "$2a$10$BiOMQp/YSE8ngo1yed0TieW6pY30ewtV5kHgfXnzmTAWUD4usO7zi");
        } else {
            throw new UsernameNotFoundException(String.format("User %s was not found", login));
        }
    }
}
