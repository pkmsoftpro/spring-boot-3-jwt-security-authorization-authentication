package com.jwtauthorization.security.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Integer> {

    Optional<Role> findByRoleId(Integer roleId);
    Optional<Role> findByName(String name);

}