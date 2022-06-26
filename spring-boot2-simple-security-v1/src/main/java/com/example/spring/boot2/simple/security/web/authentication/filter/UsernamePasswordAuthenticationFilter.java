package com.example.spring.boot2.simple.security.web.authentication.filter;

import com.example.spring.boot2.simple.security.core.Authentication;
import com.example.spring.boot2.simple.security.core.AuthenticationException;
import com.example.spring.boot2.simple.security.core.UsernamePasswordAuthenticationToken;
import com.example.spring.boot2.simple.security.core.context.SecurityContext;
import com.example.spring.boot2.simple.security.core.context.SecurityContextHolder;
import com.example.spring.boot2.simple.security.web.authentication.AuthenticationFailureHandler;
import com.example.spring.boot2.simple.security.web.authentication.AuthenticationManager;
import com.example.spring.boot2.simple.security.web.authentication.AuthenticationSuccessHandler;
import com.example.spring.boot2.simple.security.web.util.matcher.RegexRequestMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

public class UsernamePasswordAuthenticationFilter extends GenericFilterBean {

    private static final Logger LOGGER = LoggerFactory.getLogger(UsernamePasswordAuthenticationFilter.class);

    private AuthenticationManager authenticationManager = new AuthenticationManager();

    private AuthenticationSuccessHandler successHandler = new AuthenticationSuccessHandler();

    private AuthenticationFailureHandler failureHandler = new AuthenticationFailureHandler();

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        // filter chain proxy internal web config for this filter
        if (!requiresAuthentication(request, response)) {
            chain.doFilter(request, response);
            return;
        }

        Authentication authenticationResult;
        try {
            LOGGER.debug("Request is to attempt authentication");
            authenticationResult = attemptAuthentication(request, response);
            if (authenticationResult == null) {
                // continue filter chain
                chain.doFilter(request, response);
            } else {
                HttpSession session = request.getSession(false);
                if (session != null) {
                    request.changeSessionId();
                }
                successfulAuthentication(request, response, chain, authenticationResult);
                chain.doFilter(request, response);
            }
        } catch (AuthenticationException failed) {
            LOGGER.error("An internal error occurred while trying to authenticate the user.", failed);
            unsuccessfulAuthentication(request, response, failed);
        }
    }

    private boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        // this filter only for request: POST /login
        RegexRequestMatcher requestMatcher = new RegexRequestMatcher("/login", "POST");
        if (requestMatcher.matches(request)) {
            final String requestURI = request.getRequestURI();
            LOGGER.info("POST requestURI is : {}", requestURI);
            return "/login".equals(requestURI);
        }

        return false;
    }

    /**
     * Performs actual authentication.
     * <p>
     * The implementation should do one of the following:
     * <ol>
     * <li>Return a populated authentication token for the authenticated user, indicating
     * successful authentication</li>
     * <li>Return null, indicating that the authentication process is still in progress.
     * Before returning, the implementation should perform any additional work required to
     * complete the process.</li>
     * <li>Throw an <tt>AuthenticationException</tt> if the authentication process fails</li>
     * </ol>
     *
     * @return the authenticated user token, or null if authentication is incomplete.
     * @throws AuthenticationException if authentication fails.
     */
    protected Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = obtainParamter(request, "username");
        String password = obtainParamter(request, "password");

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, password);
        return this.authenticationManager.authenticate(authentication);
    }

    protected String obtainParamter(HttpServletRequest request, String parameter) {
        return request.getParameter(parameter);
    }

    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {
        LOGGER.debug("Updated SecurityContextHolder to contain : {}", authentication);
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);

        successHandler.onAuthenticationSuccess(request, response, authentication);
    }

    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        SecurityContextHolder.clearContext();

        LOGGER.error("Authentication request failed: " + failed.toString(), failed);
        LOGGER.debug("Updated SecurityContextHolder to contain null Authentication");

        failureHandler.onAuthenticationFailure(request, response, failed);
    }

}
