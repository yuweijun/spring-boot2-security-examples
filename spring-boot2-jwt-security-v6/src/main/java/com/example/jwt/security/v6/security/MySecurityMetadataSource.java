package com.example.jwt.security.v6.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public class MySecurityMetadataSource implements FilterInvocationSecurityMetadataSource, SecurityMetadataSource {

    private static final Logger LOGGER = LoggerFactory.getLogger(MySecurityMetadataSource.class);

    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        Set<ConfigAttribute> allAttributes = new HashSet<>();
        allAttributes.add(new ConfigAttribute() {
            @Override
            public String getAttribute() {
                return "custom";
            }
        });
        LOGGER.info("ConfigAttribute for object : {}", object);
        return allAttributes;
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        LOGGER.info("MySecurityMetadataSource {}", clazz.getSimpleName());
        return true;
    }
}