package com.example.jwt.security.v4.security;

import com.example.jwt.security.v4.exception.CustomException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * We should use OncePerRequestFilter since we are doing a database call, there is no point in doing this more than once or extends BasicAuthenticationFilter
 */
public class JwtTokenFilter extends OncePerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtTokenFilter.class);

    private final JwtTokenProvider jwtTokenProvider;

    public JwtTokenFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        String token = jwtTokenProvider.resolveToken(httpServletRequest);
        try {
            if (jwtTokenProvider.validateToken(token)) {
                if (jwtTokenProvider.validateToken(token)) {
                    Authentication authentication = jwtTokenProvider.getAuthentication(token);
                    final Object principal = authentication.getPrincipal();
                    LOGGER.info("authentication is {} and principal is {}", authentication, principal);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                } else {
                    LOGGER.info("token is invalid : {}", token);
                }
            }

            final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.isAuthenticated()) {
                LOGGER.info("principal is {} and token is {}", authentication.getPrincipal(), token);
            }
        } catch (CustomException ex) {
            // this is very important, since it guarantees the user is not authenticated at all
            SecurityContextHolder.clearContext();
            httpServletResponse.sendError(ex.getHttpStatus().value(), ex.getMessage());
            return;
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

}
