package br.com.lbcoutinho.auth.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiController {

    // This route is accessible with Bearer authorization
    @GetMapping("/welcome")
    public String bearerWelcome() {
        String user = SecurityContextHolder.getContext().getAuthentication().getName();
        return "Welcome to the API " + user + ". You're using Bearer authorization.";
    }

    // This route is accessible with Basic authorization
    @GetMapping("/basic/welcome")
    public String basicWelcome() {
        String user = SecurityContextHolder.getContext().getAuthentication().getName();
        return "Welcome to the API " + user + ". You're using Basic authorization.";
    }

}
