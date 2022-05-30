package com.example.jwt.security.v2.service;

import org.springframework.stereotype.Service;

@Service
public class PermissionCheckService {

    public boolean hasPermission() {
        return true;
    }

}
