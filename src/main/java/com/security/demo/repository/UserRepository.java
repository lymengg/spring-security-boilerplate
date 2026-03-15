package com.security.demo.repository;

import com.security.demo.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // Spring Data JPA generates the SQL for this automatically
    Optional<User> findByUsername(String username);

    // Useful for registration checks
    Boolean existsByUsername(String username);
}
