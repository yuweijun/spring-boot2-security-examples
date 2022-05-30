package com.example.jwt.security.v3.security;

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
import org.springframework.security.core.userdetails.User;
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
        if (MediaType.APPLICATION_JSON_VALUE.equals(contentType)) {
            ObjectMapper objectMapper = new ObjectMapper();
            try {
                JsonNode jsonNode = objectMapper.readTree(request.getInputStream());
                String username = jsonNode.get("username").asText("");
                String password = jsonNode.get("password").asText("");
                username = username.trim();
                LOGGER.info("username is {}", username);
                authRequest = new UsernamePasswordAuthenticationToken(username, password);
            } catch (IOException e) {
                // must be subclass of AuthenticationException
                throw new InternalAuthenticationServiceException(e.getMessage());
            }

            setDetails(request, authRequest);
            // use custom AuthenticationManager
            return this.getAuthenticationManager().authenticate(authRequest);
        } else {
            return super.attemptAuthentication(request, response);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
        HttpServletResponse response, FilterChain chain, Authentication authResult)
        throws IOException, ServletException {
        String token = jwtTokenProvider.createToken(((User) authResult.getPrincipal()).getUsername());
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