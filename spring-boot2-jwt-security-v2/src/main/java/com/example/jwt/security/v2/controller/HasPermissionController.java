package com.example.jwt.security.v2.controller;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/example")
public class HasPermissionController {

    @PostAuthorize("hasPermission(returnObject, 'read')")
    @GetMapping("/{id}")
    public Long findById(@PathVariable long id) {
        return id;
    }

    @PreAuthorize("hasPermission(#foo, 'write')")
    @PostMapping("/echo")
    @ResponseStatus(HttpStatus.CREATED)
    public String echo(@RequestBody String foo) {
        return foo;
    }

}
