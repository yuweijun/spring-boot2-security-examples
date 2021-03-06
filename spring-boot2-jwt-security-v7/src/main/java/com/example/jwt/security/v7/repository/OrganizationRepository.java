package com.example.jwt.security.v7.repository;

import com.example.jwt.security.v7.model.Organization;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OrganizationRepository extends JpaRepository<Organization, Long> {

    Organization findByName(String name);

}
