package com.example.jwt.security.v3.service;

import org.springframework.stereotype.Service;

@Service
public class PermissionCheckService {

    public boolean hasPermission() {
        return true;
    }

}
