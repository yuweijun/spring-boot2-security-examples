package com.example.jwt.security.v7.security;

import org.aopalliance.intercept.MethodInvocation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;

import java.io.Serializable;

public class MyMethodSecurityExpressionRoot extends SecurityExpressionRoot implements MethodSecurityExpressionOperations {

    private static final Logger LOGGER = LoggerFactory.getLogger(MyMethodSecurityExpressionRoot.class);

    private Object filterObject;

    private Object returnObject;

    private Object target;

    private MethodInvocation methodInvocation;

    private boolean isAdmin;

    MyMethodSecurityExpressionRoot(Authentication a) {
        super(a);
    }

    public Object getFilterObject() {
        return filterObject;
    }

    public void setFilterObject(Object filterObject) {
        this.filterObject = filterObject;
    }

    public Object getReturnObject() {
        return returnObject;
    }

    public void setReturnObject(Object returnObject) {
        this.returnObject = returnObject;
    }

    public Object getThis() {
        return target;
    }

    /**
     * Sets the "this" property for use in expressions. Typically this will be the "this" property of the {@code JoinPoint} representing the method invocation which is being
     * protected.
     *
     * @param target the target object on which the method in is being invoked.
     */
    void setThis(Object target) {
        this.target = target;
    }

    public boolean isAdmin() {
        return isAdmin;
    }

    public void setAdmin(boolean admin) {
        this.isAdmin = admin;
    }

    public MethodInvocation getMethodInvocation() {
        return methodInvocation;
    }

    public void setMethodInvocation(MethodInvocation methodInvocation) {
        this.methodInvocation = methodInvocation;
    }

    /**
     * {@link MyDefaultMethodSecurityExpressionHandler#createSecurityExpressionRoot(Authentication, MethodInvocation)}
     * this method can inject {@link MethodInvocation} and get method info before call super.hasPermission(...)
     */
    @Override
    public boolean hasPermission(Object target, Object permission) {
        LOGGER.info("hasPermission({}, {}) for MethodInvocation : {}", target, permission, methodInvocation);
        return super.hasPermission(target, permission);
    }

    @Override
    public boolean hasPermission(Object targetId, String targetType, Object permission) {
        LOGGER.info("hasPermission({}, {}, {})", targetId, targetType, permission);
        return super.hasPermission((Serializable) targetId, targetType, permission);
    }
}