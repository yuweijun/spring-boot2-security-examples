package com.example.jwt.security.v5.repository;

import com.example.jwt.security.v5.model.Organization;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OrganizationRepository extends JpaRepository<Organization, Integer> {

    Organization findByName(String name);

}
