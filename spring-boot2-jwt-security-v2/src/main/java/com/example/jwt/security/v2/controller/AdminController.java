package com.example.jwt.security.v2.controller;

import com.example.jwt.security.v2.service.UserService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
@Api(tags = "admin")
public class AdminController {

    @Autowired
    private UserService userService;

    @Autowired
    private ModelMapper modelMapper;

    @GetMapping("/info")
    @ApiOperation(value = "${AdminController.info}")
    public Object info() {
        return SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }

}
