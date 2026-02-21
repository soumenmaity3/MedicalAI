package com.soumen.MedicalAI.Repository.doctor;

import com.soumen.MedicalAI.Model.doctor.Doctor;
import com.soumen.MedicalAI.Model.doctor.Specialization;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class DoctorDTO {
    private UUID id;
    private String full_name;
    private String email;
    private String password;
    private String license_no;
    private String clinic_name;
    private Specialization specialization;
    private int experience = 0;
    private Integer no_of_patients = 0;

    public static Object from(Doctor saveDoctor) {
        if (saveDoctor ==null){
            return null;
        }
        DoctorDTO dto = new DoctorDTO();
        dto.setId(saveDoctor.getId());
        dto.setEmail(saveDoctor.getEmail());
        dto.setExperience(saveDoctor.getExperience());
        dto.setFull_name(saveDoctor.getFull_name());
        dto.setClinic_name(saveDoctor.getClinic_name());
        dto.setLicense_no(saveDoctor.getLicense_no());
        dto.setNo_of_patients(saveDoctor.getNo_of_patients());
        dto.setSpecialization(saveDoctor.getSpecialization());
        return dto;
    }
}
