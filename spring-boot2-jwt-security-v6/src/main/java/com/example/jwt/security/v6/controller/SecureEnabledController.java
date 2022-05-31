package com.example.jwt.security.v6.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;

@RestController
@RequestMapping("/example")
public class SecureEnabledController {

    /**
     * {@link org.springframework.security.access.vote.RoleVoter#vote(Authentication, Object, Collection)}
     *
     * original RoleVoter MUST add prefix ROLE_ before authorities name, so voter.vote() will fail if authentication's authority name is not start with ROLE_
     *
     * {@link com.example.jwt.security.v6.configuration.MyMethodSecurityConfig} accessDecisionManager add new RoleVoter with prefix empty string.
     */
    @Secured({"ADMIN_PRIVILEGE", "USER_PRIVILEGE"})
    @GetMapping("/secured")
    public String secured() {
        return "accessDecisionManager add new RoleVoter().setRolePrefix('') for secureEnabled annotation @Secured";
    }

    @GetMapping("/test")
    public String test() {
        return "test without spring security annotation";
    }

}
