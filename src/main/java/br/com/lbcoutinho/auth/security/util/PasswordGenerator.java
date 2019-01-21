package br.com.lbcoutinho.auth.security.util;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class PasswordGenerator {

    public static void main(String[] args) {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        String password = "basic123";
        System.out.printf("%s = %s\n", password, bCryptPasswordEncoder.encode("basic123"));
         password = "12345";
        System.out.printf("%s = %s\n", password, bCryptPasswordEncoder.encode("basic123"));
    }
}
