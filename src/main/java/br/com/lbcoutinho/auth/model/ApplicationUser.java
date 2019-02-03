package br.com.lbcoutinho.auth.model;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Data
@AllArgsConstructor
public class ApplicationUser {

    private String login;
    private String password;

    private String name;
    private String email;
    private String phone;

    private Set<Authority> authorities;

    public ApplicationUser() {
        authorities = new HashSet<>(Arrays.asList(Authority.USER));
    }

}
