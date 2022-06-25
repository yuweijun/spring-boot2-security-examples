package com.example.spring.boot2.simple.security.web.authentication;

import com.example.spring.boot2.simple.security.core.Authentication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author yuweijun 2022-06-25.
 */
public class AuthenticationSuccessHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationSuccessHandler.class);

    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        LOGGER.info("login authenticate success for : {}", authentication);
    }

}
