package br.com.lbcoutinho.auth.security.dto;

import lombok.*;

@Data
@RequiredArgsConstructor
public class UserDetails {

    @NonNull
    private String login;
    @NonNull
    private String password;

    // TODO add other details coming from user service
}
