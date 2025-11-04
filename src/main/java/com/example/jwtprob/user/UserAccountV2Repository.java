package com.example.jwtprob.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserAccountV2Repository extends JpaRepository<UserAccountV2, Long> {

    @Query("SELECT u FROM UserAccountV2 u LEFT JOIN FETCH u.roles r LEFT JOIN FETCH r.permissions WHERE u.username = :username")
    Optional<UserAccountV2> findByUsernameWithRolesAndPermissions(String username);

    Optional<UserAccountV2> findByUsername(String username);

    boolean existsByUsername(String username);
}

