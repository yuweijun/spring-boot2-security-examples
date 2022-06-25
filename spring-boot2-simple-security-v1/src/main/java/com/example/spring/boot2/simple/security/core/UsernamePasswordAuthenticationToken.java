
package com.example.spring.boot2.simple.security.core;

import java.util.ArrayList;
import java.util.Collection;

public class UsernamePasswordAuthenticationToken implements Authentication {

    private final String principal;

    private final String credentials;

    private boolean authenticated = false;

    private Collection<String> authorities = new ArrayList<>();

    public UsernamePasswordAuthenticationToken(String principal, String credentials) {
        this.principal = principal;
        this.credentials = credentials;
    }

    @Override
    public String getPrincipal() {
        return this.principal;
    }

    @Override
    public Collection<String> getAuthorities() {
        return authorities;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public String getName() {
        return this.principal;
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        this.authenticated = authenticated;
    }

    @Override
    public String toString() {
        return "UsernamePasswordAuthenticationToken{" +
            "principal='" + principal + '\'' +
            ", credentials='" + credentials + '\'' +
            ", authenticated=" + authenticated +
            ", authorities=" + authorities +
            '}';
    }
}
