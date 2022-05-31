package com.example.jwt.security.v6.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class MyAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private static final Logger LOGGER = LoggerFactory.getLogger(MyAuthenticationToken.class);

    public MyAuthenticationToken(Object principal, Object credentials) {
        super(principal, credentials);
    }

    public MyAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
    }

    public MyAuthenticationToken(Authentication authenticate) {
        super(authenticate.getPrincipal(), authenticate.getCredentials(), authenticate.getAuthorities());
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        final Collection<GrantedAuthority> authorities = super.getAuthorities();
        LOGGER.info("super authorities is : {}", authorities);

        return authorities;
    }
}
