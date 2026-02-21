package com.soumen.MedicalAI.Repository.doctor;

import com.soumen.MedicalAI.Model.doctor.DoctorEducation;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface DoctorEducationRepo extends JpaRepository<DoctorEducation, UUID> {
}
