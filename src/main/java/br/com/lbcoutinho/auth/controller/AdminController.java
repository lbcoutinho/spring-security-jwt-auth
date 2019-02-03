package br.com.lbcoutinho.auth.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class AdminController {

    // This route is accessible with Bearer authorization
    @GetMapping("/welcome")
    public String welcomeAdmin() {
        String user = SecurityContextHolder.getContext().getAuthentication().getName();
        return "Welcome Admin API " + user + ". You're using Bearer authorization.";
    }

}
