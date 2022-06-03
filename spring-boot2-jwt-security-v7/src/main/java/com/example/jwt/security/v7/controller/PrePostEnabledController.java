package com.example.jwt.security.v7.controller;

import com.example.jwt.security.v7.service.SecurityCheckService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/example")
public class PrePostEnabledController {

    @Autowired
    private SecurityCheckService securityCheckService;

    @GetMapping("/postFilter")
    public List<String> postFilter() {
        return securityCheckService.postFilter();
    }

    @GetMapping("/customMethodSecurityMetadataSource")
    public String customMethodSecurityMetadataSource() {
        return securityCheckService.customMethodSecurityMetadataSource();
    }

    @GetMapping("/preAuthorize")
    public String preAuthorize() {
        return securityCheckService.preAuthorize();
    }

    @PreAuthorize("hasAnyAuthority('ADMIN_PRIVILEGE', 'USER_PRIVILEGE')")
    @GetMapping("/hasAuthority")
    public String hasAuthority() {
        return "hasAnyAuthority('ADMIN_PRIVILEGE', 'USER_PRIVILEGE')\")";
    }

}
