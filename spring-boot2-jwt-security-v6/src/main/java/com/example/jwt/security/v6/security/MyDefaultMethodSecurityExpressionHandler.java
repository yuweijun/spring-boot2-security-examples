package com.example.jwt.security.v6.security;

import org.aopalliance.intercept.MethodInvocation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;

public class MyDefaultMethodSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(MyDefaultMethodSecurityExpressionHandler.class);

    @Override
    public StandardEvaluationContext createEvaluationContextInternal(Authentication auth, MethodInvocation mi) {
        LOGGER.info("MyDefaultMethodSecurityExpressionHandler#createEvaluationContextInternal() for mi : {}", mi);
        return new MyMethodSecurityEvaluationContext(auth, mi, getParameterNameDiscoverer());
    }

    @Override
    protected MethodSecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication, MethodInvocation invocation) {
        final MyMethodSecurityExpressionRoot root = new MyMethodSecurityExpressionRoot(authentication);
        root.setThis(invocation.getThis());
        root.setPermissionEvaluator(getPermissionEvaluator());
        root.setTrustResolver(getTrustResolver());
        root.setRoleHierarchy(getRoleHierarchy());

        final boolean admin = authentication
            .getAuthorities()
            .stream()
            .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().contains("ADMIN"));

        LOGGER.info("MyMethodSecurityExpressionRoot is admin : {}", admin);
        root.setAdmin(admin);

        return root;
    }

}
