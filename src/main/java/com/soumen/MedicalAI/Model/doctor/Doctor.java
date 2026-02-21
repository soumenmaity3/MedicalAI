package com.soumen.MedicalAI.Model.doctor;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class Doctor {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    @NotNull
    private String full_name;
    @NotNull
    private String email;
    @NotNull
    private String password;
    @NotNull
    private String license_no;
    @NotNull
    private String clinic_name;
    @NotNull
    private Specialization specialization;
    @NotNull
    private int experience = 0;

    private Integer no_of_patients = 0;

}
