package com.example.jwtprob.permission;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.Set;

@Repository
public interface PermissionRepository extends JpaRepository<Permission, Long> {

    Optional<Permission> findByResourceAndAction(String resource, String action);

    @Query("SELECT p FROM Permission p WHERE p.resource = :resource")
    Set<Permission> findAllByResource(String resource);

    boolean existsByResourceAndAction(String resource, String action);
}

