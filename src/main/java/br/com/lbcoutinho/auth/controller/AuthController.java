package br.com.lbcoutinho.auth.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    // This route is accessible with Bearer authorization
    @GetMapping("/api/test")
    public String authJwt() {
        String user = SecurityContextHolder.getContext().getAuthentication().getName();
        return "Welcome to the API " + user;
    }

    // This route is accessible with Basic authorization
    @GetMapping("/app/test")
    public String authBasic() {
        String user = SecurityContextHolder.getContext().getAuthentication().getName();
        return "Welcome to the App " + user;
    }

}
