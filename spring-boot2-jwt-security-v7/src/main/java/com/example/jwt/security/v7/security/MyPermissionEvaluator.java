package com.example.jwt.security.v7.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;

public class MyPermissionEvaluator implements PermissionEvaluator {

    private static final Logger LOGGER = LoggerFactory.getLogger(MyPermissionEvaluator.class);

    @Override
    public boolean hasPermission(Authentication auth, Object targetDomainObject, Object permission) {
        if ((auth == null) || (targetDomainObject == null) || !(permission instanceof String)) {
            LOGGER.warn("hasPermission(Authentication auth, Object targetDomainObject, Object permission) return false");
            return false;
        }
        if (targetDomainObject instanceof String) {
            return hasPrivilege(auth, targetDomainObject.toString().toUpperCase(), permission.toString().toUpperCase());
        }

        String targetType = targetDomainObject.getClass().getSimpleName().toUpperCase();
        return hasPrivilege(auth, targetType, permission.toString().toUpperCase());
    }

    @Override
    public boolean hasPermission(Authentication auth, Serializable targetId, String targetType, Object permission) {
        if ((auth == null) || (targetType == null) || !(permission instanceof String)) {
            LOGGER.info("hasPermission(Authentication auth, Serializable targetId, String targetType, Object permission) return false");
            return false;
        }
        return hasPrivilege(auth, targetType.toUpperCase(), permission.toString().toUpperCase());
    }

    private boolean hasPrivilege(Authentication authentication, String targetType, String permission) {
        for (GrantedAuthority grantedAuth : authentication.getAuthorities()) {
            final String authority = grantedAuth.getAuthority();
            // for admin
            if (authority.equals("ADMIN_PRIVILEGE")) {
                LOGGER.info("hasPrivilege('ADMIN', {}, {})", targetType, permission);
                return true;
            }

            if (permission.equals("READ")) {
                if (authority.equals(targetType + "_PRIVILEGE")) {
                    return true;
                }
            } else if (permission.equals("WRITE")) {
                if (authority.equals(targetType + "_WRITE_PRIVILEGE")) {
                    return true;
                }
            }
        }

        LOGGER.info("hasPrivilege(Authentication auth, String targetType, String permission) return false");
        return false;
    }
}
