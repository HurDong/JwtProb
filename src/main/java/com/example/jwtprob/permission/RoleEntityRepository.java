package com.example.jwtprob.permission;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.Set;

@Repository
public interface RoleEntityRepository extends JpaRepository<RoleEntity, String> {

    Optional<RoleEntity> findByName(String name);

    boolean existsByName(String name);

    @Query("SELECT r FROM RoleEntity r JOIN FETCH r.permissions WHERE r.name IN :names")
    Set<RoleEntity> findAllByNameIn(Set<String> names);
}

