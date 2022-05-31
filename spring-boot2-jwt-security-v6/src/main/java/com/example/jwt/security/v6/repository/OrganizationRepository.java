package com.example.jwt.security.v6.repository;

import com.example.jwt.security.v6.model.Organization;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OrganizationRepository extends JpaRepository<Organization, Long> {

    Organization findByName(String name);

}
