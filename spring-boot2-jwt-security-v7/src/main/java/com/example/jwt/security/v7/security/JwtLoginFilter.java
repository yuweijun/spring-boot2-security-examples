package com.example.jwt.security.v7.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtLoginFilter extends UsernamePasswordAuthenticationFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtLoginFilter.class);

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
        throws AuthenticationException {
        LOGGER.info("{}#attemptAuthentication", getClass().getSimpleName());
        UsernamePasswordAuthenticationToken authRequest = null;
        final String contentType = request.getContentType();
        String username, password;
        if (MediaType.APPLICATION_JSON_VALUE.equals(contentType)) {
            ObjectMapper objectMapper = new ObjectMapper();
            try {
                JsonNode jsonNode = objectMapper.readTree(request.getInputStream());
                username = jsonNode.get("username").asText("");
                password = jsonNode.get("password").asText("");
            } catch (IOException e) {
                // must be subclass of AuthenticationException
                throw new InternalAuthenticationServiceException(e.getMessage());
            }
        } else {
            LOGGER.info("attemptAuthentication for contentType : {}", contentType);
            username = obtainUsername(request);
            password = obtainPassword(request);
        }

        authRequest = new MyAuthenticationToken(username, password);
        setDetails(request, authRequest);
        // use custom AuthenticationManager
        final Authentication authenticate = this.getAuthenticationManager().authenticate(authRequest);
        return new MyAuthenticationToken(authenticate);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
        HttpServletResponse response, FilterChain chain, Authentication authResult)
        throws IOException, ServletException {
        String token = jwtTokenProvider.createToken(((UserDetails) authResult.getPrincipal()).getUsername());
        response.addHeader("Authorization", "Bearer " + token);
        super.successfulAuthentication(request, response, chain, authResult);
    }

    /**
     * this method will be invoke if {@link #attemptAuthentication(HttpServletRequest request, HttpServletResponse response)} throw exception
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        super.unsuccessfulAuthentication(request, response, failed);
    }
}