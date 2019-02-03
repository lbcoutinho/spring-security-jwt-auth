package br.com.lbcoutinho.auth.security.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class UserCredentials {

    private String login;
    private String password;

}
