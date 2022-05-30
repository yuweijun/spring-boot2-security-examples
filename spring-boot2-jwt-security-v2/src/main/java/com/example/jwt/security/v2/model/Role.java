package com.example.jwt.security.v2.model;

import org.springframework.security.core.GrantedAuthority;

public enum Role implements GrantedAuthority {

    ROLE_ADMIN,
    ROLE_CLIENT,
    ROLE_USER;

    public String getAuthority() {
        return name();
    }

}
