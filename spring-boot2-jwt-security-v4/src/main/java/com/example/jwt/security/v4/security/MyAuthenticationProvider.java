package com.example.jwt.security.v4.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Collection;

/**
 * <pre>
 * example of spring security AuthenticationProvider is
 * {@link org.springframework.security.authentication.dao.DaoAuthenticationProvider}
 *
 * this MyAuthenticationProvider will be added to {@link ProviderManager#getProviders()}
 * </pre>
 */
@Component
public class MyAuthenticationProvider implements AuthenticationProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(MyAuthenticationProvider.class);

    @Autowired
    private JwtTokenBasedUserDetails jwtTokenBasedUserDetails;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = (String) authentication.getPrincipal();
        String password = authentication.getCredentials().toString();

        return authenticate(username, password);
    }

    public MyAuthenticationToken authenticate(String username, String password) {
        UserDetails userDetails = jwtTokenBasedUserDetails.loadUserByUsername(username);
        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            LOGGER.error("Authentication failed: password does not match stored value");
            throw new BadCredentialsException("MyAuthenticationProvider Bad credentials");
        }

        final Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
        LOGGER.info("userDetails authorities is : {}", authorities);
        MyAuthenticationToken authenticationToken = new MyAuthenticationToken(userDetails, password, authorities);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        LOGGER.info("add user token to SecurityContext for username : {}", username);
        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}