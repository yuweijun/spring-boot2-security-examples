package com.example.jwt.security.v5.controller;

import com.example.jwt.security.v5.model.Organization;
import com.example.jwt.security.v5.repository.OrganizationRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
public class OrganizationController {

    @Autowired
    private OrganizationRepository organizationRepository;

    @PreAuthorize("isAdmin()")
    @GetMapping("/organizations/{id}")
    @ResponseBody
    public Organization findOrgById(@PathVariable long id) {
        final Optional<Organization> optional = organizationRepository.findById(id);
        return optional.orElseThrow(() -> new IllegalArgumentException("not found for id : " + id));
    }

}
