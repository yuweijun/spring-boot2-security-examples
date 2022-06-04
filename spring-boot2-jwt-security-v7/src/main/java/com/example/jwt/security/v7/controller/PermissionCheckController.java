package com.example.jwt.security.v7.controller;

import com.example.jwt.security.v7.configuration.PermissionCheck;
import com.example.jwt.security.v7.service.UserService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/permission/check")
@Api(tags = "permissionCheck")
public class PermissionCheckController {

    @Autowired
    private UserService userService;

    @GetMapping("/index")
    @ApiOperation(value = "${PermissionCheckController.index}")
    @PermissionCheck("USER")
    public String index() {
        return "@PermissionCheck(\"USER\")";
    }

}
