package com.example.jwt.security.v5.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

public class MyFilter implements Filter {

    private static final Logger LOGGER = LoggerFactory.getLogger(MyFilter.class);

    public MyFilter() {
        LOGGER.info("MyFilter init");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        LOGGER.info("custom servlet filter");
        chain.doFilter(request, response);
    }

}