package com.soumen.MedicalAI.Repository.doctor;

import com.soumen.MedicalAI.Model.doctor.Doctor;
import jakarta.validation.constraints.NotNull;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface DoctorRepo extends JpaRepository<Doctor, UUID> {

    boolean existsByEmailIgnoreCase(@NotNull String email);

    Optional<Doctor> findByEmailIgnoreCase(String email);
}
