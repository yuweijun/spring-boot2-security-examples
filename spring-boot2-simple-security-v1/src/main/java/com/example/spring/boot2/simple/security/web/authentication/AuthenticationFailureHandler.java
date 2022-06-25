package com.example.spring.boot2.simple.security.web.authentication;

import com.example.spring.boot2.simple.security.core.AuthenticationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author yuweijun 2022-06-25.
 */
public class AuthenticationFailureHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationFailureHandler.class);

    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) {
        LOGGER.error("login authenticate failure");
    }

}
