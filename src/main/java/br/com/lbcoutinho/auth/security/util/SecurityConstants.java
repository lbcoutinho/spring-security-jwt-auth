package br.com.lbcoutinho.auth.security.util;

public final class SecurityConstants {

    // TODO extract constants to config server
    public static final long EXPIRATION_TIME = 24 * 60 * 60 * 1000; // One day
    public static final String JWT_SECRET = "124v7n891v47n891v89fy89h1";
    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String BEARER_PREFIX = "Bearer ";

    private SecurityConstants() {
    }
}
