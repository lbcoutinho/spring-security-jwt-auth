package br.com.lbcoutinho.auth.security.util;

public final class SecurityConstants {

    public static final long EXPIRATION_TIME = 24 * 60 * 60 * 1000; // 30 days
    public static final String JWT_SECRET = "124v7n891v47n891v89fy89h1";
    public static final String BEARER_PREFIX = "Bearer ";
    public static final String BASIC_PREFIX = "Basic ";

    public static final String NAME = "name";
    public static final String EMAIL = "email";
    public static final String PHONE = "phone";
    public static final String AUTHORITIES = "auth";

    public static final String ENCODED_PASSWORD_12345 = "$2a$10$BiOMQp/YSE8ngo1yed0TieW6pY30ewtV5kHgfXnzmTAWUD4usO7zi";

    private SecurityConstants() {
    }

}
