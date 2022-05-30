package com.example.jwt.security.v4.security;

import org.aopalliance.intercept.MethodInvocation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;

import java.util.Collection;

public class MyAccessDecisionManager implements AccessDecisionManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(MyAccessDecisionManager.class);

    /**
     * @param authentication   认证对象就是前面认证过称返回了Authentication，如果你返回的是自定义的，那么这里的具体类型就是你自定义的类
     * @param object           spring security使用 cglib 代理的controller类的方法返回的对象在FilterSecurityInterceptor中，decide的参数object类型为FilterInvocation，
     *                         MethodSecurityInterceptor中object类型为MethodInvocation，具体类型是 ReflectiveMethodInvocation 如果你自定义的话，这里的object类型可以变成自己定义的类型
     * @param configAttributes SecurityMetadataSource返回的 关于这个object的权限集合
     */
    @Override
    public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes)
        throws AccessDeniedException, InsufficientAuthenticationException {
        if (object instanceof FilterInvocation) {
            LOGGER.info("FilterSecurityInterceptor for object : {}", object);
        } else if (object instanceof MethodInvocation) {
            LOGGER.info("MethodSecurityInterceptor for object : {}", object);
        } else {
            LOGGER.info("object is {}", object);
        }
        // custom authentication logic and throws AccessDeniedException if failed
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        LOGGER.info("MyAccessDecisionManager supports ConfigAttribute : {}", attribute);
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        LOGGER.info("MyAccessDecisionManager supports class : {}", clazz.getSimpleName());
        return true;
    }
}