package com.example.spring.boot2.simple.security.controller;

import com.example.spring.boot2.simple.security.core.Authentication;
import com.example.spring.boot2.simple.security.core.context.SecurityContextHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

/**
 * @author yuweijun 2022-06-24.
 */
@Controller
public class LoginController {

    private static final Logger LOGGER = LoggerFactory.getLogger(LoginController.class);

    @GetMapping("/login")
    public String index() {
        return "login";
    }

    @PostMapping("/login")
    public String login() {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        LOGGER.info("post to login page for : {}", authentication.getPrincipal());
        return "redirect:/";
    }

}
