package br.com.lbcoutinho.auth.security.authentication;

import br.com.lbcoutinho.auth.model.ApplicationUser;
import br.com.lbcoutinho.auth.model.Authority;
import br.com.lbcoutinho.auth.security.dto.UserCredentials;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.Getter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.Set;

import static br.com.lbcoutinho.auth.security.util.SecurityConstants.*;

/**
 * An Authentication implementation that is designed to store user login, password and authorities.
 */
@Getter
public class JWTAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private ApplicationUser user;

    /**
     * Constructor for before authentication.
     */
    public JWTAuthenticationToken(UserCredentials credentials) {
        super(credentials.getLogin(), credentials.getPassword());
    }

    /**
     * Constructor for after authentication.
     */
    public JWTAuthenticationToken(ApplicationUser user) {
        super(user.getLogin(), null, user.getAuthorities());
        this.user = user;
    }

    /**
     * Constructor for after authorization.
     */
    public JWTAuthenticationToken(DecodedJWT jwt, Set<Authority> authorities) {
        super(jwt.getSubject(), null, authorities);
        this.user = new ApplicationUser();
        user.setLogin(jwt.getSubject());
        user.setAuthorities(authorities);
        user.setName(jwt.getClaim(NAME).asString());
        user.setEmail(jwt.getClaim(EMAIL).asString());
        user.setPhone(jwt.getClaim(PHONE).asString());
    }

}
