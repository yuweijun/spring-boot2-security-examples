package com.example.jwt.security.v7.controller;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/has/permission")
public class HasPermissionController {

    @PreAuthorize("@permissionCheckService.hasPermission(authentication, 'read')")
    @GetMapping("/read")
    public boolean read() {
        return true;
    }

    @PreAuthorize("@permissionCheckService.hasPermission(#message, 'write')")
    @GetMapping("/echo")
    @ResponseStatus(HttpStatus.CREATED)
    public String echo(String message) {
        return message;
    }

    @PreAuthorize("hasPermission('USER', 'read')")
    @GetMapping("/check2")
    public String check2() {
        return "@PreAuthorize(\"hasPermission('USER', 'read')\")";
    }

    @PreAuthorize("hasPermission('id', 'USER', 'read')")
    @GetMapping("/check3")
    public String check3() {
        return "@PreAuthorize(\"hasPermission('id', 'USER', 'read')\")";
    }

}
