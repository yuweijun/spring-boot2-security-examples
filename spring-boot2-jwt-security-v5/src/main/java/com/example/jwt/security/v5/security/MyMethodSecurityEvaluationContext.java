package com.example.jwt.security.v5.security;

import org.aopalliance.intercept.MethodInvocation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.aop.support.AopUtils;
import org.springframework.context.expression.MethodBasedEvaluationContext;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.parameters.DefaultSecurityParameterNameDiscoverer;

import java.lang.reflect.Method;

public class MyMethodSecurityEvaluationContext extends MethodBasedEvaluationContext {

    private static final Logger LOGGER = LoggerFactory.getLogger(MyMethodSecurityEvaluationContext.class);

    public MyMethodSecurityEvaluationContext(Authentication user, MethodInvocation mi) {
        this(user, mi, new DefaultSecurityParameterNameDiscoverer());
    }

    MyMethodSecurityEvaluationContext(Authentication user, MethodInvocation mi,
        ParameterNameDiscoverer parameterNameDiscoverer) {
        super(mi.getThis(), getSpecificMethod(mi), mi.getArguments(), parameterNameDiscoverer);
    }

    private static Method getSpecificMethod(MethodInvocation mi) {
        LOGGER.info("get specified method : {}", mi);
        return AopUtils.getMostSpecificMethod(mi.getMethod(), AopProxyUtils.ultimateTargetClass(mi.getThis()));
    }
}

