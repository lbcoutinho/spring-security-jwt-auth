package br.com.lbcoutinho.auth.security.service;

import br.com.lbcoutinho.auth.security.authentication.JWTAuthenticationToken;
import br.com.lbcoutinho.auth.security.dto.UserCredentials;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.junit.jupiter.api.Assertions.assertAll;

@ExtendWith(SpringExtension.class)
class UserAuthenticationProviderTest {

    private static UserAuthenticationProvider userAuthenticationProvider;

    @BeforeAll
    static void beforeAll() {
        userAuthenticationProvider = new UserAuthenticationProvider(new BCryptPasswordEncoder());
    }

    @Test
    void givenJWTAuthenticationTokenClass_whenSupports_thenReturnIsTrue() {
        assertThat(userAuthenticationProvider.supports(JWTAuthenticationToken.class)).isTrue();
    }

    @Test
    void givenUserThatDoesNotExist_whenAuthenticate_thenThrowsUsernameNotFoundException() {
        // Given
        String login = "user-x";
        JWTAuthenticationToken auth = new JWTAuthenticationToken(new UserCredentials(login, "12345"));

        // Then
        assertThatExceptionOfType(UsernameNotFoundException.class).isThrownBy(() -> userAuthenticationProvider.authenticate(auth))
                .withMessage("User %s was not found", login)
                .withNoCause();
    }

    @Test
    void givenWrongPassword_whenAuthenticate_thenThrowsBadCredentialsException() {
        // Given
        JWTAuthenticationToken auth = new JWTAuthenticationToken(new UserCredentials("user1", "wrong-password"));

        // Then
        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> userAuthenticationProvider.authenticate(auth))
                .withMessage("Incorrect password")
                .withNoCause();
    }

    @Test
    void givenValidCredentials_whenAuthenticate_thenJWTAuthenticationTokenIsReturned() {
        // Given
        String login = "user1";
        JWTAuthenticationToken auth = new JWTAuthenticationToken(new UserCredentials(login, "12345"));

        // When
        JWTAuthenticationToken authResult = (JWTAuthenticationToken) userAuthenticationProvider.authenticate(auth);

        // Then
        assertAll(
                () -> assertThat(authResult.getPrincipal()).isEqualTo(login),
                () -> assertThat(authResult.getUser()).isNotNull()
        );
    }

}
