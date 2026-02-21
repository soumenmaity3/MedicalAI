package com.soumen.MedicalAI.Repository;

import com.soumen.MedicalAI.Model.users.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<Users, UUID> {

    /**
     * Find user by email address
     * Uses Spring Data JPA naming convention
     */
    Optional<Users> findByEmailIgnoreCase(String email);

    /**
     * Check if user exists by email
     * Returns true if user exists, false otherwise
     */
    boolean existsByEmailIgnoreCase(String email);

}
