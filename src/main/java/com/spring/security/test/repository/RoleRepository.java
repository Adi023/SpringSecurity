package com.spring.security.test.repository;


import org.springframework.data.jpa.repository.JpaRepository;

import com.spring.security.test.entity.Role;
import com.spring.security.test.entity.RoleType;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(RoleType name);
}

