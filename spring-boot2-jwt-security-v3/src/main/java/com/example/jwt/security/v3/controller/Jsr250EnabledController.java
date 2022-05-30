package com.example.jwt.security.v3.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;

/**
 * JSR-250 not enabled and access is valid
 */
@RestController
@RequestMapping("/example")
public class Jsr250EnabledController {

    @DenyAll
    @GetMapping("/denyAll")
    public String denyAll() {
        return "JSR-250@DenyAll";
    }

    @PermitAll
    @GetMapping("/permitAll")
    public String permitAll() {
        return "JSR-250@PermitAll";
    }

    @RolesAllowed({"ROLE_ADMIN", "ROLE_USER"})
    @GetMapping("/rolesAllowed")
    public String rolesAllowed() {
        return "JSR-250@RolesAllowed";
    }
}
