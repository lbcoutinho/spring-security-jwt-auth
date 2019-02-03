package br.com.lbcoutinho.auth.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ApplicationUser {

    private String login;
    private String password;

    private String name;
    private String email;
    private String phone;

    private Set<Authority> authorities;

}
