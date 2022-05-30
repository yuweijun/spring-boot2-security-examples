package com.example.jwt.security.v3.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.util.Collection;

public class MyFilterSecurityInterceptor extends FilterSecurityInterceptor implements Filter {

    private static final Logger LOGGER = LoggerFactory.getLogger(MyFilterSecurityInterceptor.class);

    private FilterInvocationSecurityMetadataSource securityMetadataSource;

    public MyFilterSecurityInterceptor() {
        LOGGER.info("MyFilterSecurityInterceptor init");
    }

    public FilterInvocationSecurityMetadataSource getSecurityMetadataSource() {
        return securityMetadataSource;
    }

    public void setSecurityMetadataSource(FilterInvocationSecurityMetadataSource securityMetadataSource) {
        this.securityMetadataSource = securityMetadataSource;
    }

    @Override
    public void invoke(FilterInvocation fi) throws IOException, ServletException {
        LOGGER.info("FilterInvocation fi Holds objects associated with a HTTP filter : {}", fi);
        Collection<ConfigAttribute> attributes = this.obtainSecurityMetadataSource().getAttributes(fi);
        LOGGER.info("obtain security metadata source from FilterInvocation fi : {}", attributes);
        fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
    }

    @Override
    public Class<?> getSecureObjectClass() {
        // 这里的 Class 类型就是beforeInvocation 参数 object 的类型
        return FilterInvocation.class;
    }

    @Override
    public SecurityMetadataSource obtainSecurityMetadataSource() {
        return securityMetadataSource;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        FilterInvocation fi = new FilterInvocation(request, response, chain);

        // for test
        final String pattern = "/users/**";
        AntPathRequestMatcher antPathRequestMatcher = new AntPathRequestMatcher(pattern);
        final boolean matches = antPathRequestMatcher.matches(fi.getRequest());
        LOGGER.info("AntPathRequestMatcher match {} result : {}", pattern, matches);

        invoke(fi);
    }
}