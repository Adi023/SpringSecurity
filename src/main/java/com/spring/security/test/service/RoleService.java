package com.spring.security.test.service;

import java.util.List;

import org.springframework.stereotype.Service;
import com.spring.security.test.entity.Role;
import com.spring.security.test.repository.RoleRepository;

@Service
public class RoleService {

    private final RoleRepository roleRepository;

    public RoleService(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    public List<Role> getAllRoles() {
        return roleRepository.findAll();
    }

    public Role saveRole(Role role) {
        return roleRepository.save(role);
    }
}
