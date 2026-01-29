package com.soumen.MedicalAI.Repository;

import com.soumen.MedicalAI.Model.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<Users, UUID> {


    @Query(value = "SELECT * FROM med_users WHERE email=:email", nativeQuery = true)
    Optional<Users> existByEmail(String email);

//    Users findByEmail(String username);
    Optional<Users> findByEmail(String email);

}
