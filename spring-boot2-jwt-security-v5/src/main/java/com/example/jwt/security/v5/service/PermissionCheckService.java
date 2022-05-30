package com.example.jwt.security.v5.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
public class PermissionCheckService {

    private static final Logger LOGGER = LoggerFactory.getLogger(PermissionCheckService.class);

    public boolean hasPermission(Authentication authentication, String permission) {
        LOGGER.info("permission is : {}", permission);
        LOGGER.info("authentication is : {}", authentication);
        return true;
    }

    public boolean hasPermission(String message, String permission) {
        LOGGER.info("message is {} and permission is : {}", message, permission);
        return true;
    }

}
