package com.example.spring.boot2.simple.security.controller;

import com.example.spring.boot2.simple.security.core.Authentication;
import com.example.spring.boot2.simple.security.core.context.SecurityContext;
import com.example.spring.boot2.simple.security.core.context.SecurityContextHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author yuweijun 2022-06-25.
 */
@RestController
public class UserController {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserController.class);

    @GetMapping("/user")
    public String user() {
        final SecurityContext context = SecurityContextHolder.getContext();
        LOGGER.info("get principal page for context : {}", context);
        final Authentication authentication = context.getAuthentication();
        if (authentication != null) {
            return authentication.getPrincipal();
        }

        return "principle is not set";
    }

    @GetMapping("/authentication")
    public Authentication authentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }
}
