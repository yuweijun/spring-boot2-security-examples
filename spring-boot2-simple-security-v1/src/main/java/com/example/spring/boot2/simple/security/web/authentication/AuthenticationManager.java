package com.example.spring.boot2.simple.security.web.authentication;

import com.example.spring.boot2.simple.security.core.Authentication;
import com.example.spring.boot2.simple.security.core.AuthenticationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;

/**
 * @author yuweijun 2022-06-25.
 */
public class AuthenticationManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationManager.class);

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        authentication.setAuthenticated(true);
        final Collection<String> authorities = authentication.getAuthorities();
        authorities.add("ADMIN");
        authorities.add("USER");

        LOGGER.info("AuthenticationManager#authenticate() for : {}", authorities);
        return authentication;
    }
}
