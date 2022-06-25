package com.example.spring.boot2.simple.security.core.context;

import com.example.spring.boot2.simple.security.core.Authentication;

import java.util.Objects;

public class SecurityContextImpl implements SecurityContext {

    private Authentication authentication;

    public SecurityContextImpl() {
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof SecurityContextImpl) {
            if (Objects.equals(this.getAuthentication(), ((SecurityContextImpl) obj).getAuthentication())) {
                return true;
            }
        }

        return false;
    }

    @Override
    public Authentication getAuthentication() {
        return authentication;
    }

    @Override
    public int hashCode() {
        if (this.authentication == null) {
            return -1;
        } else {
            return this.authentication.hashCode();
        }
    }

    @Override
    public void setAuthentication(Authentication authentication) {
        this.authentication = authentication;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(super.toString());

        if (this.authentication == null) {
            sb.append(": Null authentication");
        } else {
            sb.append(": Authentication: ").append(this.authentication);
        }

        return sb.toString();
    }
}
