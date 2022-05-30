package com.example.jwt.security.v2.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/example")
public class SecureEnabledController {

    @Secured({"ROLE_ADMIN", "ROLE_USER"})
    @GetMapping("/secured")
    public String secured() {
        return "secureEnabled@Secured";
    }

    @GetMapping("/test")
    public String test() {
        return "test without spring security annotation";
    }

}
