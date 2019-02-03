package br.com.lbcoutinho.auth.security.service;

import br.com.lbcoutinho.auth.model.ApplicationUser;
import br.com.lbcoutinho.auth.security.authentication.JWTAuthenticationToken;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

import static br.com.lbcoutinho.auth.model.Authority.ADMIN;
import static br.com.lbcoutinho.auth.model.Authority.USER;
import static br.com.lbcoutinho.auth.security.util.SecurityConstants.ENCODED_PASSWORD_12345;

/**
 * Retrieves user details from ApplicationUser Service and performs password comparison.
 */
@Service
@Slf4j
public class UserAuthenticationProvider implements AuthenticationProvider {

    // List simulate users in database
    private static final List<ApplicationUser> USERS;

    static {
        USERS = new ArrayList<>();
        USERS.add(new ApplicationUser("user1", ENCODED_PASSWORD_12345, "Users 1", "user1@gmail.com", "999991111",
                new HashSet<>(Arrays.asList(USER))));
        USERS.add(new ApplicationUser("user2", ENCODED_PASSWORD_12345, "Users 2", "user2@gmail.com", "999992222",
                new HashSet<>(Arrays.asList(USER))));
        USERS.add(new ApplicationUser("admin", ENCODED_PASSWORD_12345, "Administrator", "admin@gmail.com", "999998888",
                new HashSet<>(Arrays.asList(USER, ADMIN))));
    }

    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    public UserAuthenticationProvider(BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String login = authentication.getName();
        String password = authentication.getCredentials().toString();
        log.trace("UserServiceAuthenticationProvider.authenticate - login={} / password={}", login, password);

        ApplicationUser user = getUserDetails(login);
        if (bCryptPasswordEncoder.matches(password, user.getPassword())) {
            log.trace("Password matches - returning UsernamePasswordAuthenticationToken");
            return new JWTAuthenticationToken(user);
        } else {
            throw new BadCredentialsException("Incorrect password");
        }
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return JWTAuthenticationToken.class.equals(aClass);
    }

    private ApplicationUser getUserDetails(String login) throws AuthenticationException {
        return USERS.stream()
                .filter(u -> u.getLogin().equals(login))
                .findFirst()
                .orElseThrow(() -> new UsernameNotFoundException(String.format("User %s was not found", login)));
    }
}
