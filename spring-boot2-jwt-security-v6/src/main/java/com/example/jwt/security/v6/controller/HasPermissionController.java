package com.example.jwt.security.v6.controller;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/example")
public class HasPermissionController {

    @PostAuthorize("@permissionCheckService.hasPermission(authentication, 'read')")
    @GetMapping("/hasPermission/read")
    public boolean read() {
        return true;
    }

    @PreAuthorize("@permissionCheckService.hasPermission(#message, 'write')")
    @GetMapping("/hasPermission/echo")
    @ResponseStatus(HttpStatus.CREATED)
    public String echo(String message) {
        return message;
    }

}
