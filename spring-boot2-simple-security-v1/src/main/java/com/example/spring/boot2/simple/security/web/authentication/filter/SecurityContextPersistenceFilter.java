package com.example.spring.boot2.simple.security.web.authentication.filter;

import com.example.spring.boot2.simple.security.core.context.SecurityContext;
import com.example.spring.boot2.simple.security.core.context.SecurityContextHolder;
import com.example.spring.boot2.simple.security.web.authentication.AuthenticationSessionRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SecurityContextPersistenceFilter extends GenericFilterBean {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityContextPersistenceFilter.class);

    private AuthenticationSessionRepository sessionRepository = new AuthenticationSessionRepository();

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        try {
            SecurityContext contextBeforeChainExecution = sessionRepository.loadContext(request);
            if (contextBeforeChainExecution != null) {
                LOGGER.info("load context before chain execution : {}", contextBeforeChainExecution);
                SecurityContextHolder.setContext(contextBeforeChainExecution);
            }

            chain.doFilter(request, response);
        } finally {
            // context maybe generated next filter such as UsernamePasswordAuthenticationFilter
            SecurityContext contextAfterChainExecution = SecurityContextHolder.getContext();
            LOGGER.info("load context after chain execution : {}", contextAfterChainExecution);

            // Crucial removal of SecurityContextHolder contents - do this before anything else.
            SecurityContextHolder.clearContext();
            sessionRepository.saveContext(contextAfterChainExecution, request, response);
        }
    }

}
